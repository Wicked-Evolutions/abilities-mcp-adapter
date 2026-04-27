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

if ( ! function_exists( 'oauth_is_mcp_resource_request' ) ) {
	/**
	 * Whether the current REST request targets the MCP resource endpoint (C-1, H.1.2).
	 *
	 * Bearer auth must be a no-op for any other URI: tokens are bound to
	 * /wp-json/mcp/mcp-adapter-default-server, but `determine_current_user`
	 * fires on every REST request. Without this gate a token issued for the
	 * MCP resource silently authenticates the bound user on /wp-json/wp/v2/*,
	 * /wp-json/wp/v2/plugins, etc. — where the H.1.3 scope enforcer never
	 * fires — effectively turning the Bearer into a session cookie.
	 *
	 * Matches both pretty-permalinks (/wp-json/<ns>/<route>) and plain-permalinks
	 * (?rest_route=/<ns>/<route>).
	 */
	function oauth_is_mcp_resource_request(): bool {
		$uri = $_SERVER['REQUEST_URI'] ?? '';
		if ( ! is_string( $uri ) || $uri === '' ) {
			return false;
		}

		$rest_route = '/mcp/mcp-adapter-default-server';

		// Pretty permalinks. Derive the path from rest_url() so subdir / multisite
		// installs (e.g. /wp/wp-json/...) are matched against their actual prefix.
		if ( function_exists( 'rest_url' ) ) {
			$resource_url  = (string) rest_url( 'mcp/mcp-adapter-default-server' );
			$resource_path = (string) parse_url( $resource_url, PHP_URL_PATH );
			if ( $resource_path !== '' && str_starts_with( $uri, $resource_path ) ) {
				$tail = substr( $uri, strlen( $resource_path ) );
				if ( $tail === '' || $tail[0] === '/' || $tail[0] === '?' ) {
					return true;
				}
			}
		}

		// Plain permalinks: ?rest_route=/mcp/mcp-adapter-default-server.
		$query = (string) parse_url( $uri, PHP_URL_QUERY );
		if ( $query !== '' ) {
			parse_str( $query, $params );
			$route = (string) ( $params['rest_route'] ?? '' );
			if ( $route === $rest_route || str_starts_with( $route, $rest_route . '/' ) ) {
				return true;
			}
		}

		return false;
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
