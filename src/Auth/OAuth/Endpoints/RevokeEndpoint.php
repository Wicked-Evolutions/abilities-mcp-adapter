<?php
/**
 * Token revocation endpoint (RFC 7009).
 *
 * Always returns 200 regardless of whether the token existed.
 * GET probe returns informational JSON (L2 lesson).
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints;

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
	 * POST — revoke a token. Always 200 per RFC 7009.
	 */
	public static function handle_post( \WP_REST_Request $request ): never {
		$params = $request->get_params();
		$token  = $params['token'] ?? '';

		if ( $token ) {
			TokenStore::revoke_by_plaintext( (string) $token );
			\oauth_log_boundary( 'boundary.oauth_token_revoked', [ 'reason' => 'explicit_revocation' ] );
		}

		// RFC 7009: always 200, even when token not found.
		\token_success( [] );
	}
}
