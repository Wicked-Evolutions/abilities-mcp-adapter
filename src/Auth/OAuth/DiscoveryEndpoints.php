<?php
/**
 * OAuth 2.1 discovery endpoint handlers.
 *
 * Serves three .well-known paths (RFC 9728, RFC 8414, OIDC fallback).
 * Intercepted at init priority 0, before WordPress routing.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

/**
 * Builds and serves the three OAuth discovery documents.
 */
final class DiscoveryEndpoints {

	/** REST namespace used by the MCP adapter. */
	private const MCP_NAMESPACE = 'mcp';
	private const MCP_ROUTE     = 'mcp-adapter-default-server';
	private const OAUTH_REST_NS = 'mcp'; // OAuth endpoints under same namespace as MCP.

	/**
	 * Compute the issuer URL from HTTP_HOST (timing-safe, avoids home_url() at init priority 0).
	 * Validated against OAuthHostAllowlist before this is called.
	 */
	public static function issuer(): string {
		$scheme = oauth_is_https() ? 'https' : 'http';
		$host   = $_SERVER['HTTP_HOST'] ?? 'unknown';
		// Strip port for issuer (issuer should not include port per RFC 8414 §2).
		$host   = explode( ':', $host )[0];
		return $scheme . '://' . $host;
	}

	/**
	 * MCP resource URL — always constructed dynamically from issuer.
	 * Namespace confirmed by Stream D: rest_url('mcp/mcp-adapter-default-server').
	 */
	public static function resource_url(): string {
		return self::issuer() . '/wp-json/' . self::MCP_NAMESPACE . '/' . self::MCP_ROUTE;
	}

	/**
	 * REST base for OAuth endpoints (under /wp-json/).
	 */
	private static function oauth_rest_base(): string {
		return self::issuer() . '/wp-json/' . self::OAUTH_REST_NS;
	}

	/**
	 * Serve RFC 9728 — Protected Resource Metadata.
	 * Access-Control-Allow-Origin: * (public metadata, per H.4.4).
	 */
	public static function serve_protected_resource(): never {
		self::json_response( [
			'resource'                 => self::resource_url(),
			'authorization_servers'    => [ self::issuer() ],
			'scopes_supported'         => ScopeRegistry::all_scopes(),
			'bearer_methods_supported' => [ 'header' ],
			'resource_documentation'   => 'https://wickedevolutions.com/docs/abilities-mcp/oauth',
		], cors: true );
	}

	/**
	 * Serve RFC 8414 — Authorization Server Metadata.
	 */
	public static function serve_authorization_server(): never {
		self::json_response( self::as_metadata(), cors: true );
	}

	/**
	 * Serve OIDC Discovery fallback (L1, L5 lessons from Appendix D).
	 * We do NOT issue ID tokens — metadata omits OIDC-specific fields to signal this.
	 */
	public static function serve_oidc_configuration(): never {
		self::json_response( self::as_metadata(), cors: true );
	}

	/**
	 * Authorization server metadata body (shared by RFC 8414 + OIDC endpoints).
	 */
	private static function as_metadata(): array {
		$base = self::oauth_rest_base();
		return [
			'issuer'                                => self::issuer(),
			'authorization_endpoint'                => self::issuer() . '/oauth/authorize',
			'token_endpoint'                        => $base . '/oauth/token',
			'registration_endpoint'                 => $base . '/oauth/register',
			'revocation_endpoint'                   => $base . '/oauth/revoke',
			'scopes_supported'                      => ScopeRegistry::all_scopes(),
			'response_types_supported'              => [ 'code' ],
			'grant_types_supported'                 => [ 'authorization_code', 'refresh_token' ],
			'code_challenge_methods_supported'      => [ 'S256' ],
			'token_endpoint_auth_methods_supported' => [ 'none' ],
			// Intentionally omit: id_token_signing_alg_values_supported, subject_types_supported,
			// userinfo_endpoint — we serve this for client-discovery compat ONLY. No ID tokens.
		];
	}

	/**
	 * Emit a JSON response and exit.
	 * Discovery endpoints: CORS open. All others: no CORS (H.4.4).
	 */
	public static function json_response( array $data, int $status = 200, bool $cors = false ): never {
		http_response_code( $status );
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Cache-Control: no-store' );
		if ( $cors ) {
			header( 'Access-Control-Allow-Origin: *' );
		}
		echo wp_json_encode( $data, JSON_UNESCAPED_SLASHES );
		exit;
	}
}
