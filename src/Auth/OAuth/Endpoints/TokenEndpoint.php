<?php
/**
 * OAuth token endpoint — authorization_code and refresh_token grants.
 *
 * All responses via TokenEndpointResponse helper (H.3.7):
 * Cache-Control: no-store, correct RFC 6749 §5.2 status codes, no CORS.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints;

use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationCodeStore;
use WickedEvolutions\McpAdapter\Auth\OAuth\ClientRegistry;
use WickedEvolutions\McpAdapter\Auth\OAuth\TokenStore;

/**
 * Handles GET and POST /oauth/token.
 */
final class TokenEndpoint {

	/** GET probe — L2 (H.2.6 lesson). */
	public static function handle_get( \WP_REST_Request $request ): \WP_REST_Response {
		return new \WP_REST_Response( [
			'endpoint'    => 'oauth/token',
			'methods'     => [ 'POST' ],
			'grant_types' => [ 'authorization_code', 'refresh_token' ],
		], 200 );
	}

	/** POST — dispatch by grant_type. */
	public static function handle_post( \WP_REST_Request $request ): never {
		$params     = $request->get_params();
		$grant_type = sanitize_text_field( $params['grant_type'] ?? '' );

		match ( $grant_type ) {
			'authorization_code' => self::handle_auth_code( $params ),
			'refresh_token'      => self::handle_refresh( $params ),
			default              => \token_error( 'unsupported_grant_type', 'Only authorization_code and refresh_token are supported.', 400 ),
		};
	}

	/** authorization_code grant. */
	private static function handle_auth_code( array $params ): never {
		$code         = sanitize_text_field( $params['code'] ?? '' );
		$client_id    = sanitize_text_field( $params['client_id'] ?? '' );
		$redirect_uri = esc_url_raw( $params['redirect_uri'] ?? '' );
		$code_verifier = $params['code_verifier'] ?? '';

		if ( ! $code || ! $client_id || ! $redirect_uri || ! $code_verifier ) {
			\token_error( 'invalid_request', 'code, client_id, redirect_uri, and code_verifier are required.', 400 );
		}

		// Verify client exists (invalid_client → 401).
		$client = ClientRegistry::find( $client_id );
		if ( ! $client ) {
			\token_error( 'invalid_client', 'Client not found or revoked.', 401 );
		}

		// Consume code: verifies PKCE + client_id + redirect_uri bindings (H.1.1).
		$code_row = AuthorizationCodeStore::consume( $code, $client_id, $redirect_uri, $code_verifier );
		if ( ! $code_row ) {
			\token_error( 'invalid_grant', 'Authorization code is invalid, expired, or already used.', 400 );
		}

		// Issue token pair.
		$token = TokenStore::issue(
			$client_id,
			(int) $code_row->user_id,
			$code_row->scope,
			$code_row->resource
		);

		\oauth_log_boundary( 'boundary.oauth_token_issued', [
			'client_id' => $client_id,
			'user_id'   => (int) $code_row->user_id,
		] );

		\token_success( $token );
	}

	/** refresh_token grant. */
	private static function handle_refresh( array $params ): never {
		$refresh_token = $params['refresh_token'] ?? '';
		$client_id     = sanitize_text_field( $params['client_id'] ?? '' );

		if ( ! $refresh_token || ! $client_id ) {
			\token_error( 'invalid_request', 'refresh_token and client_id are required.', 400 );
		}

		$client = ClientRegistry::find( $client_id );
		if ( ! $client ) {
			\token_error( 'invalid_client', 'Client not found or revoked.', 401 );
		}

		$result = TokenStore::rotate( $refresh_token, $client_id );

		if ( $result === null ) {
			\oauth_log_boundary( 'boundary.oauth_token_revoked', [ 'client_id' => $client_id, 'reason' => 'refresh_replay_or_invalid' ] );
			\token_error( 'invalid_grant', 'Refresh token is invalid, expired, or has been revoked.', 400 );
		}

		if ( isset( $result['__idempotent_retry__'] ) ) {
			// Within 30-second grace — we can't return the original plaintext (hashed).
			// Return an error that tells the bridge to wait and retry — it still has the token.
			// In practice the bridge should re-use the access token it already has.
			\token_error( 'invalid_grant', 'Refresh already rotated. Use current access token or retry after grace window.', 400 );
		}

		\oauth_log_boundary( 'boundary.oauth_token_refreshed', [ 'client_id' => $client_id ] );

		\token_success( $result );
	}
}
