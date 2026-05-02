<?php
/**
 * Dynamic Client Registration endpoint (RFC 7591).
 *
 * GET probe returns informational JSON (L2 lesson — some clients probe before POST).
 * POST registers a new client, enforcing rate limits and redirect_uri validation.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints;

use WickedEvolutions\McpAdapter\Auth\OAuth\ClientRegistry;
use WickedEvolutions\McpAdapter\Auth\OAuth\DiscoveryEndpoints;
use WickedEvolutions\McpAdapter\Auth\OAuth\RateLimiter;
use WickedEvolutions\McpAdapter\Auth\OAuth\ScopeRegistry;

/**
 * Handles GET and POST /oauth/register.
 */
final class RegisterEndpoint {

	/**
	 * GET probe — L2: return informational JSON, not 404.
	 */
	public static function handle_get( \WP_REST_Request $request ): \WP_REST_Response {
		return new \WP_REST_Response( [
			'endpoint'    => 'oauth/register',
			'methods'     => [ 'POST' ],
			'description' => 'Dynamic Client Registration per RFC 7591',
		], 200 );
	}

	/**
	 * POST — register a new client.
	 */
	public static function handle_post( \WP_REST_Request $request ): never {
		$ip = \oauth_client_ip();

		// Rate limit check (H.3.3).
		$check = RateLimiter::check_dcr( $ip );
		if ( $check !== true ) {
			header( 'Retry-After: ' . $check );
			DiscoveryEndpoints::json_response(
				[ 'error' => 'temporarily_unavailable', 'error_description' => 'Too many registrations. Try again later.' ],
				429
			);
		}

		// Site-wide cap.
		if ( RateLimiter::site_cap_reached() ) {
			DiscoveryEndpoints::json_response(
				[ 'error' => 'temporarily_unavailable', 'error_description' => 'Registration limit reached for this site.' ],
				503
			);
		}

		$body          = $request->get_json_params() ?? [];
		$client_name   = sanitize_text_field( $body['client_name'] ?? 'Unknown Bridge' );
		$redirect_uris = $body['redirect_uris'] ?? [];
		$software_id   = sanitize_text_field( $body['software_id'] ?? '' );
		$software_ver  = sanitize_text_field( $body['software_version'] ?? '' );
		$scope         = sanitize_text_field( $body['scope'] ?? 'abilities:read' );

		// Validate redirect_uris present and array.
		if ( empty( $redirect_uris ) || ! is_array( $redirect_uris ) ) {
			DiscoveryEndpoints::json_response(
				[ 'error' => 'invalid_redirect_uri', 'error_description' => 'redirect_uris is required and must be an array.' ],
				400
			);
		}

		// Validate each redirect_uri: must be loopback HTTP or HTTPS. localhost rejected (RFC 8252 §7.3).
		foreach ( $redirect_uris as $uri ) {
			if ( ! self::is_valid_redirect_uri( (string) $uri ) ) {
				DiscoveryEndpoints::json_response(
					[ 'error' => 'invalid_redirect_uri', 'error_description' => 'redirect_uri must be http://127.0.0.1/... or https://...' ],
					400
				);
			}
		}

		// Validate scopes — drop unknown scopes silently (be liberal in what we accept).
		$classification             = self::classify_scopes( $scope );
		$valid_scopes               = $classification['valid'];
		$sensitive_scopes_requested = $classification['sensitive'];
		$scope                      = implode( ' ', $valid_scopes ) ?: 'abilities:read';

		// Register.
		$client_id = ClientRegistry::register(
			$client_name,
			$redirect_uris,
			$scope,
			$software_id,
			$software_ver,
			$ip
		);

		RateLimiter::record_dcr( $ip );

		\oauth_log_boundary( 'boundary.oauth_client_registered', [
			'client_id'  => $client_id,
			'ip'         => $ip,
		] );

		// L-3: surface any sensitive scopes the client requested so the bridge
		// (and the Connected Bridges admin UI) can show "X sensitive scopes
		// requested — will require explicit consent" instead of conflating
		// registration with consent. Storage is unchanged: the DCR record
		// continues to hold every valid scope including sensitive ones, since
		// sensitive scopes are gated at /oauth/authorize per H.3.4 and never
		// land on a token without explicit operator consent.
		DiscoveryEndpoints::json_response( [
			'client_id'                  => $client_id,
			'client_id_issued_at'        => time(),
			'client_name'                => $client_name,
			'redirect_uris'              => $redirect_uris,
			'grant_types'                => [ 'authorization_code', 'refresh_token' ],
			'response_types'             => [ 'code' ],
			'token_endpoint_auth_method' => 'none',
			'scope'                      => $scope,
			'sensitive_scopes_requested' => $sensitive_scopes_requested,
		], 201 );
	}

	/**
	 * Classify a space-separated scope string into valid known scopes and
	 * the subset of those that are sensitive (per `ScopeRegistry::is_sensitive`).
	 *
	 * Unknown scopes are dropped silently (RFC 7591 §2.1 — server may modify
	 * the requested scope set). Sensitive scopes are kept in the valid set —
	 * gating happens at consent time, not at registration.
	 *
	 * @return array{valid: string[], sensitive: string[]}
	 */
	public static function classify_scopes( string $scope_str ): array {
		$requested = '' === $scope_str ? array() : explode( ' ', $scope_str );
		$valid     = array_values( array_filter(
			$requested,
			fn( $s ) => in_array( $s, ScopeRegistry::all_scopes(), true )
		) );
		$sensitive = array_values( array_filter( $valid, [ ScopeRegistry::class, 'is_sensitive' ] ) );

		return array(
			'valid'     => $valid,
			'sensitive' => $sensitive,
		);
	}

	/**
	 * Validate a redirect_uri.
	 * Loopback: http://127.0.0.1:PORT/... allowed. localhost rejected.
	 * Non-loopback: https:// only.
	 */
	private static function is_valid_redirect_uri( string $uri ): bool {
		$parsed = parse_url( $uri );
		$scheme = $parsed['scheme'] ?? '';
		$host   = $parsed['host'] ?? '';

		$is_loopback = in_array( $host, [ '127.0.0.1', '::1' ], true );
		if ( $is_loopback && $scheme === 'http' ) {
			return true;
		}
		if ( $scheme === 'https' ) {
			return true;
		}
		return false;
	}
}
