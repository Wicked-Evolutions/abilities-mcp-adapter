<?php
/**
 * Role switcher constraint logic (Appendix H.4.5).
 *
 * The consent screen lets the operator authorize the bridge as one of their
 * own WordPress roles — but only roles they actually possess. A tampered form
 * cannot escalate (Editor cannot select Admin even if they edit the DOM):
 * the POST handler re-checks the submitted role against this same allowlist.
 *
 * Pure logic — no WP coupling beyond the WP_User shape. Tests inject a fake
 * user via the `roles_for_user_id()` injection point.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Consent;

/**
 * Determine which roles a user may authorize a bridge as.
 */
final class RoleSelector {

	/**
	 * Return the role slugs the user with the given ID currently holds.
	 *
	 * Falls back to `get_userdata()` if no injected resolver is provided —
	 * the production path. Tests can inject a callable returning string[].
	 *
	 * @param int                   $user_id WP user ID.
	 * @param callable|null         $resolver Optional `(int $user_id): string[]` for tests.
	 * @return string[] Role slugs, in WP_User->roles order. Empty array when user not found.
	 */
	public static function roles_for_user_id( int $user_id, ?callable $resolver = null ): array {
		if ( $resolver ) {
			$roles = $resolver( $user_id );
			return is_array( $roles ) ? array_values( array_filter( $roles, 'is_string' ) ) : array();
		}

		if ( ! function_exists( 'get_userdata' ) ) {
			return array();
		}

		$user = get_userdata( $user_id );
		if ( ! $user || empty( $user->roles ) || ! is_array( $user->roles ) ) {
			return array();
		}
		return array_values( array_filter( $user->roles, 'is_string' ) );
	}

	/**
	 * Verify that a submitted role is one the user actually holds.
	 *
	 * This is the H.4.5 server-side recheck. Even if the consent form was
	 * tampered to add `admin` to the role select, this method returns false
	 * for a user whose `roles` array does not contain `admin`.
	 *
	 * @param int                   $user_id        WP user ID.
	 * @param string                $submitted_role Role slug from the POST body.
	 * @param callable|null         $resolver       Optional injection for tests.
	 */
	public static function user_holds_role( int $user_id, string $submitted_role, ?callable $resolver = null ): bool {
		if ( '' === $submitted_role ) {
			return false;
		}
		return in_array( $submitted_role, self::roles_for_user_id( $user_id, $resolver ), true );
	}
}
