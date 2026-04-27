<?php
/**
 * OAuth scope enforcement for ability execution (H.1.3).
 *
 * Issue #38: every DCR-issued bearer token had effective write access to any
 * ability the underlying user could execute, regardless of the scopes it was
 * granted. Phase 1 populated `OAuthRequestContext` from the bearer-auth filter
 * but never wired a consumer that gates ability execution against the granted
 * scope set. This class is that consumer.
 *
 * The gate runs at exactly one location — `ToolsHandler::handle_tool_call` —
 * before `$ability->execute( $args )` fires. Non-OAuth requests pass through
 * unchanged (WP capabilities govern; the gate becomes a no-op).
 *
 * Scope mapping rule per issue #38 / Appendix A:
 *
 *   required_scope = abilities:<category>:<permission>
 *
 * where `category` comes from `WP_Ability::get_category()` and `permission`
 * comes from `PermissionManager::get_permission( $ability )`.
 *
 * Sensitive scopes (per `ScopeRegistry::SENSITIVE_SCOPES`) are NEVER implied
 * by an umbrella grant — they require an explicit grant. Issued tokens have
 * pre-expanded scope strings (umbrella + non-sensitive children, see
 * `AuthorizeRequestValidator::validate`), so the granted set already contains
 * the matching child scope when the umbrella alone was requested. The umbrella
 * fallback below is defense-in-depth: it ensures the contract holds even for
 * tokens issued by a future code path that stores umbrellas verbatim.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

use WickedEvolutions\McpAdapter\Admin\PermissionManager;

/**
 * Maps abilities to required scopes and gates execution against the granted set.
 */
final class OAuthScopeEnforcer {

	/**
	 * Compute the canonical scope string required to execute the given ability.
	 *
	 * Falls back to `mcp-adapter` when the ability has no category, matching the
	 * ability namespace used by the adapter's own meta-abilities.
	 */
	public static function required_scope_for( \WP_Ability $ability ): string {
		$permission = PermissionManager::get_permission( $ability );
		$category   = self::category_segment( $ability );

		return sprintf( 'abilities:%s:%s', $category, $permission );
	}

	/**
	 * Gate the given ability against the current OAuth request context.
	 *
	 * - Non-OAuth requests: returns null (allow; WP caps govern).
	 * - OAuth requests with the required scope OR a permitted umbrella: returns null.
	 * - OAuth requests missing the scope: emits a `boundary.oauth_scope_denied`
	 *   event and returns a structured error array naming the missing scope.
	 *
	 * @return array|null Null when allowed; otherwise an array with shape
	 *                    `[ 'error_code' => string, 'message' => string,
	 *                       'required_scope' => string ]`.
	 */
	public static function check( \WP_Ability $ability ): ?array {
		if ( ! OAuthRequestContext::is_oauth_request() ) {
			return null;
		}

		$required = self::required_scope_for( $ability );
		$granted  = OAuthRequestContext::granted_scopes();

		// Direct match — the required scope is explicitly in the granted set.
		if ( in_array( $required, $granted, true ) ) {
			return null;
		}

		// Sensitive scopes never implied by umbrella — only an explicit grant counts.
		// Direct match above already handles the explicit case; if we got here, deny.
		if ( ! ScopeRegistry::is_sensitive( $required ) ) {
			$umbrella = self::umbrella_for( $required );
			if ( null !== $umbrella && in_array( $umbrella, $granted, true ) ) {
				return null;
			}
		}

		// Deny. Log a structured boundary event (metadata only, allowlisted tags).
		\oauth_log_boundary( 'boundary.oauth_scope_denied', array(
			'client_id'  => (string) OAuthRequestContext::client_id(),
			'reason'     => 'insufficient_scope',
			'error_code' => $required,
		) );

		return array(
			'error_code'     => 'insufficient_scope',
			'message'        => sprintf( 'Required scope: %s', $required ),
			'required_scope' => $required,
		);
	}

	/**
	 * Extract the category segment used in the canonical scope string.
	 *
	 * `WP_Ability::get_category()` may return either an enum-like string
	 * (`content`, `users`, …) or be missing entirely on minimally-registered
	 * abilities. Default to `mcp-adapter` for the latter — that namespace is
	 * already in `ScopeRegistry::all_scopes()`.
	 */
	private static function category_segment( \WP_Ability $ability ): string {
		$category = method_exists( $ability, 'get_category' ) ? (string) $ability->get_category() : '';
		$category = trim( $category );

		if ( '' === $category ) {
			return 'mcp-adapter';
		}

		return $category;
	}

	/**
	 * The umbrella scope that, when granted, implies the given non-sensitive scope.
	 * Returns null when the scope shape doesn't match `abilities:<category>:<op>`
	 * or when the operation has no umbrella (only read/write/delete have umbrellas).
	 */
	private static function umbrella_for( string $required ): ?string {
		$parts = explode( ':', $required );
		if ( count( $parts ) !== 3 || 'abilities' !== $parts[0] ) {
			return null;
		}
		$op = $parts[2];
		if ( ! in_array( $op, array( 'read', 'write', 'delete' ), true ) ) {
			return null;
		}

		$umbrella = 'abilities:' . $op;
		if ( ! isset( ScopeRegistry::UMBRELLA_IMPLICATIONS[ $umbrella ] ) ) {
			return null;
		}
		// Only count as a valid umbrella if the scope is in the umbrella's implication set.
		// This guards against future scopes that exist but aren't covered by an umbrella.
		if ( ! in_array( $required, ScopeRegistry::UMBRELLA_IMPLICATIONS[ $umbrella ], true ) ) {
			return null;
		}

		return $umbrella;
	}
}
