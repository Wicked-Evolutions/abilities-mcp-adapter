<?php
/**
 * Per-request OAuth context: scope propagation from bearer validation to ability execution.
 *
 * Populated by the bearer-auth filter; consumed by ability execution scope checks.
 * Must never be cached — reset at the start of each request.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

/**
 * Singleton holding granted OAuth scope for the current HTTP request.
 */
final class OAuthRequestContext {

	private static ?array $current = null;

	/**
	 * Populate context after successful bearer token validation.
	 *
	 * @param int    $user_id   WP user the token is bound to.
	 * @param array  $scopes    Granted scope strings.
	 * @param string $resource  Resource URL the token was issued for.
	 * @param string $client_id DCR-issued client identifier.
	 * @param int    $token_id  Row ID from kl_oauth_tokens.
	 */
	public static function set( int $user_id, array $scopes, string $resource, string $client_id, int $token_id ): void {
		self::$current = compact( 'user_id', 'scopes', 'resource', 'client_id', 'token_id' );
	}

	/** Whether the current request was authenticated via an OAuth bearer token. */
	public static function is_oauth_request(): bool {
		return self::$current !== null;
	}

	/** WP user ID bound to the current token. Null when not an OAuth request. */
	public static function user_id(): ?int {
		return self::$current['user_id'] ?? null;
	}

	/** Scope strings granted on this token. Empty when not an OAuth request. */
	public static function granted_scopes(): array {
		return self::$current['scopes'] ?? [];
	}

	public static function client_id(): ?string {
		return self::$current['client_id'] ?? null;
	}

	public static function token_id(): ?int {
		return self::$current['token_id'] ?? null;
	}

	public static function resource(): ?string {
		return self::$current['resource'] ?? null;
	}

	/** Clear — call at the start of each request in test contexts. */
	public static function reset(): void {
		self::$current = null;
	}

	/**
	 * Whether the current OAuth request has the given scope explicitly granted.
	 *
	 * Strict contract (M-3, 2026-04-27 audit):
	 *   - Non-OAuth request → false. Callers MUST handle the non-OAuth path
	 *     explicitly (e.g. fall back to `current_user_can( ... )`). Returning
	 *     true here previously made the API trivially fail-open if a future
	 *     caller used it as the sole authorization gate.
	 *   - OAuth request, scope present in granted set → true.
	 *   - OAuth request, scope absent → false.
	 *
	 * Match is direct `in_array` — sensitive scopes are NEVER implied by
	 * umbrella grants (see ScopeRegistry::SENSITIVE_SCOPES). For umbrella-
	 * aware non-sensitive scope expansion, route through
	 * `OAuthScopeEnforcer::check_scope()` instead.
	 *
	 * Renamed from `has_scope()` to make the OAuth-specific semantics obvious
	 * at every call site.
	 */
	public static function oauth_has_scope( string $required_scope ): bool {
		if ( ! self::is_oauth_request() ) {
			return false;
		}
		return in_array( $required_scope, self::$current['scopes'], true );
	}
}
