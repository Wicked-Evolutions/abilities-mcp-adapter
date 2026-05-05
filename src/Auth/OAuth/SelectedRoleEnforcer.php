<?php
/**
 * Selected-role capability downgrade for OAuth-bound requests (#88).
 *
 * When a multi-role operator picks a single role at the consent screen
 * (Appendix H.4.5 role switcher), that choice is persisted on the auth-code
 * → access-token → refresh-token chain and surfaced via OAuthRequestContext::
 * selected_role(). This enforcer wires the persisted role into WordPress'
 * capability resolution: for the OAuth-bound user on this request, $allcaps
 * is replaced with the chosen role's capability map. All other users on the
 * same request, and all non-OAuth requests, are passed through untouched.
 *
 * Why a `user_has_cap` filter instead of mutating $current_user->roles /
 * allcaps directly: this is request-scoped, reversible, and orthogonal to
 * code that reads the user object directly. Selected-role is an OAuth-
 * session concept, not a user-record concept — `$user->roles` continues to
 * reflect the operator's actual roles on their underlying user record.
 *
 * Lookup is via wp_roles()->roles[$role]['capabilities'] by default;
 * a callable can be injected for tests.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

/**
 * Apply the OAuthRequestContext-supplied selected_role as a cap downgrade.
 */
final class SelectedRoleEnforcer {

	/**
	 * Optional resolver injected by tests.
	 *
	 * Signature: (string $role_slug): array<string, bool>
	 *
	 * Production path uses {@see default_role_capabilities()} which reads
	 * {@see wp_roles()}.
	 */
	private static $resolver = null;

	/**
	 * Inject a custom role-capabilities resolver. Tests only.
	 *
	 * @param callable|null $resolver Pass null to restore the default.
	 */
	public static function set_resolver( ?callable $resolver ): void {
		self::$resolver = $resolver;
	}

	/**
	 * `user_has_cap` filter handler.
	 *
	 * Filter signature (WP core):
	 *   apply_filters( 'user_has_cap', $allcaps, $caps, $args, $user )
	 *
	 * Pass-through paths (in order):
	 *   1. Not an OAuth request — request was authenticated by a non-Bearer
	 *      mechanism (cookie, application password, etc.); selected_role does
	 *      not apply.
	 *   2. selected_role is empty — single-role operator, or a token issued
	 *      via the auto-approve path. Today's behavior preserved (full caps).
	 *   3. The user being checked is not the OAuth-bound user — defensive
	 *      guard for code that does cap checks against arbitrary users
	 *      (e.g. admin UI checking another user's caps); we never downgrade
	 *      a user that did not authenticate via this token.
	 *
	 * On the downgrade path, $allcaps is replaced wholesale with the role's
	 * capability map. The role's caps are looked up at filter time (not
	 * cached on context) so that capability changes via filters like
	 * `role_has_cap` or runtime role-cap edits are reflected on the next
	 * cap check, matching how WP normally resolves caps.
	 *
	 * @param array         $allcaps All caps the user is asserted to have.
	 * @param array         $caps    Capabilities required for this check.
	 * @param array         $args    Original args to current_user_can / similar.
	 * @param object|\WP_User|null $user  The user being checked.
	 * @return array
	 */
	public static function apply( $allcaps, $caps, $args, $user ): array {
		if ( ! is_array( $allcaps ) ) {
			$allcaps = array();
		}

		if ( ! OAuthRequestContext::is_oauth_request() ) {
			return $allcaps;
		}

		$role = OAuthRequestContext::selected_role();
		if ( '' === $role ) {
			return $allcaps;
		}

		$bound_user_id = OAuthRequestContext::user_id();
		if ( null === $bound_user_id ) {
			return $allcaps;
		}

		$checked_user_id = self::user_id_from( $user );
		if ( null === $checked_user_id || $checked_user_id !== $bound_user_id ) {
			return $allcaps;
		}

		return self::role_capabilities( $role );
	}

	/**
	 * Resolve a role slug to its capability map ([cap_name => bool]).
	 *
	 * Returns an empty map when the role is unknown — defensive: an unknown
	 * role results in zero caps rather than full caps. An OAuth request bound
	 * to an unknown selected_role should fail closed.
	 */
	public static function role_capabilities( string $role_slug ): array {
		if ( '' === $role_slug ) {
			return array();
		}
		if ( null !== self::$resolver ) {
			$caps = call_user_func( self::$resolver, $role_slug );
			return is_array( $caps ) ? $caps : array();
		}
		return self::default_role_capabilities( $role_slug );
	}

	/**
	 * Default resolver: read the role's capabilities from wp_roles().
	 *
	 * Returns an empty array when wp_roles() is unavailable (CLI bootstrap
	 * or test environment without the function defined) or the role is
	 * unknown — fail-closed semantics.
	 */
	private static function default_role_capabilities( string $role_slug ): array {
		if ( ! function_exists( 'wp_roles' ) ) {
			return array();
		}
		$roles = wp_roles();
		if ( ! is_object( $roles ) || empty( $roles->roles[ $role_slug ]['capabilities'] ) ) {
			return array();
		}
		$caps = $roles->roles[ $role_slug ]['capabilities'];
		return is_array( $caps ) ? $caps : array();
	}

	/** Best-effort extraction of the user ID from the filter's `$user` argument. */
	private static function user_id_from( $user ): ?int {
		if ( is_object( $user ) && isset( $user->ID ) ) {
			return (int) $user->ID;
		}
		if ( is_numeric( $user ) ) {
			return (int) $user;
		}
		return null;
	}
}
