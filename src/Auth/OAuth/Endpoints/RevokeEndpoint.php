<?php
/**
 * Token revocation endpoint (RFC 7009).
 *
 * Always returns 200 regardless of whether the token existed.
 * GET probe returns informational JSON (L2 lesson).
 *
 * H-2: RFC 7009 §2.1 — client authentication required. For public clients
 * (token_endpoint_auth_method: none) registered via DCR, "client authentication"
 * means the caller must present the client_id they registered with, and that
 * client_id must match the one stored on the token. This reading is consistent
 * with RFC 7009 §2.1 ("The authorization server MUST require client
 * authentication for confidential clients or for any client that was issued
 * client credentials") and with MCP-protocol clients that are always public.
 * For public clients the client_id-binding check is the proof of possession.
 *
 * M-7: Per-IP rate limiting (20/min, 200/hr) and client_id logged in boundary
 * event so revocation is auditable even when the token lookup fails.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints;

use WickedEvolutions\McpAdapter\Auth\OAuth\RateLimiter;
use WickedEvolutions\McpAdapter\Auth\OAuth\TokenStore;

/**
 * Handles GET and POST /oauth/revoke.
 */
final class RevokeEndpoint {

	/** GET probe. */
	public static function handle_get( \WP_REST_Request $request ): \WP_REST_Response {
		return new \WP_REST_Response( [
			'endpoint'    => 'oauth/revoke',
			'methods'     => [ 'POST' ],
			'description' => 'Token revocation per RFC 7009',
		], 200 );
	}

	/**
	 * POST — revoke a token. Always 200 per RFC 7009 (even on auth failure or
	 * unknown token) to avoid leaking token existence.
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function handle_post( \WP_REST_Request $request ): never {
		$ip = \oauth_client_ip();

		// M-7: per-IP rate limit for the revoke endpoint.
		$rate = RateLimiter::check_revoke( $ip );
		if ( $rate !== true ) {
			\oauth_log_boundary( 'boundary.oauth_revoke_rate_limited', [ 'ip' => $ip ] );
			\token_error( 'rate_limit_exceeded', 'Too many revocation requests. Retry after ' . $rate . ' seconds.', 429 );
		}
		RateLimiter::record_revoke( $ip );

		$params    = $request->get_params();
		$token     = (string) ( $params['token'] ?? '' );
		$client_id = (string) ( $params['client_id'] ?? '' );

		if ( $token === '' ) {
			// RFC 7009: missing token is not an error; just return 200.
			\token_success( [] );
		}

		// H-2: verify the caller is the legitimate client that was issued this token.
		// Look up the token's stored client_id. If the token doesn't exist, silently
		// succeed (RFC 7009 §2.2 — revocation of unknown tokens is not an error).
		$meta = TokenStore::find_token_meta( $token );

		if ( $meta !== null ) {
			if ( $client_id === '' || ! hash_equals( (string) $meta->client_id, $client_id ) ) {
				// Wrong or missing client_id — log and silently succeed (no info leak).
				\oauth_log_boundary( 'boundary.oauth_revoke_client_mismatch', [
					'ip'            => $ip,
					'client_hint'   => $client_id !== '' ? $client_id : '(none)',
					'reason'        => 'client_id_mismatch',
				] );
				\token_success( [] );
			}

			// Client verified — revoke with family cascade (H-2).
			TokenStore::revoke_by_plaintext( $token );
			\oauth_log_boundary( 'boundary.oauth_token_revoked', [
				'client_id' => $meta->client_id,
				'reason'    => 'explicit_revocation',
			] );
		}

		// RFC 7009: always 200, even when token not found.
		\token_success( [] );
	}
}
