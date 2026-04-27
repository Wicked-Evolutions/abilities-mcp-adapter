<?php
/**
 * Global OAuth helper functions.
 *
 * Defined in the GLOBAL namespace (no namespace declaration in this file)
 * so they are accessible from all OAuth endpoint classes via `\function_name()`
 * regardless of the calling class's namespace.
 *
 * Loaded once by AuthorizationServer::boot() and again by tests/bootstrap.php.
 * Each function is guarded by function_exists() so re-inclusion is safe.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

if ( ! function_exists( 'oauth_client_ip' ) ) {
	/**
	 * Return the client IP, respecting trusted proxy headers only when
	 * WP_OAUTH_TRUST_FORWARDED_HOST is defined and true (H.2.5).
	 */
	function oauth_client_ip(): string {
		if ( defined( 'WP_OAUTH_TRUST_FORWARDED_HOST' ) && WP_OAUTH_TRUST_FORWARDED_HOST ) {
			$forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
			if ( $forwarded ) {
				return trim( explode( ',', $forwarded )[0] );
			}
		}
		return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
	}
}

if ( ! function_exists( 'oauth_is_https' ) ) {
	/**
	 * Determine whether the current request is HTTPS (H.2.5).
	 */
	function oauth_is_https(): bool {
		if ( function_exists( 'is_ssl' ) && is_ssl() ) {
			return true;
		}
		if ( defined( 'WP_OAUTH_TRUST_FORWARDED_HOST' ) && WP_OAUTH_TRUST_FORWARDED_HOST ) {
			return ( $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '' ) === 'https';
		}
		return false;
	}
}

if ( ! function_exists( 'oauth_read_auth_header' ) ) {
	/**
	 * Read the Authorization header with fallbacks for FastCGI/PHP-FPM (H.2.6).
	 *
	 * Order: apache_request_headers() → getallheaders() → $_SERVER['HTTP_AUTHORIZATION']
	 *        → $_SERVER['REDIRECT_HTTP_AUTHORIZATION'].
	 */
	function oauth_read_auth_header(): ?string {
		if ( function_exists( 'apache_request_headers' ) ) {
			foreach ( apache_request_headers() as $k => $v ) {
				if ( strtolower( $k ) === 'authorization' ) {
					return $v;
				}
			}
		}
		if ( function_exists( 'getallheaders' ) ) {
			foreach ( getallheaders() as $k => $v ) {
				if ( strtolower( $k ) === 'authorization' ) {
					return $v;
				}
			}
		}
		return $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null;
	}
}

if ( ! function_exists( 'oauth_log_boundary' ) ) {
	/**
	 * Emit an OAuth event to the boundary log.
	 * Metadata only — never logs token values, hashes, codes, or redirect URLs (H.4.3).
	 */
	function oauth_log_boundary( string $event, array $tags = [] ): void {
		if ( function_exists( 'do_action' ) ) {
			do_action( 'mcp_adapter_boundary_event', $event, $tags, null );
		}
	}
}

if ( ! function_exists( 'token_error' ) ) {
	/**
	 * Emit a token endpoint error response per RFC 6749 §5.2 and exit (H.3.7).
	 */
	function token_error( string $error, string $description, int $status = 400 ): never {
		status_header( $status );
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Cache-Control: no-store, no-cache, max-age=0' );
		header( 'Pragma: no-cache' );
		echo wp_json_encode( [ 'error' => $error, 'error_description' => $description ] );
		exit;
	}
}

if ( ! function_exists( 'token_success' ) ) {
	/**
	 * Emit a token endpoint success response per RFC 6749 §5.1 and exit (H.3.7).
	 */
	function token_success( array $body, int $status = 200 ): never {
		status_header( $status );
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Cache-Control: no-store, no-cache, max-age=0' );
		header( 'Pragma: no-cache' );
		echo wp_json_encode( $body, JSON_UNESCAPED_SLASHES );
		exit;
	}
}
