<?php
/**
 * Origin header validator for MCP HTTP transport.
 *
 * Defense-in-depth against DNS-rebinding. Independent of authentication —
 * an allowed Origin without auth still gets 401; valid auth from a
 * disallowed Origin still gets 403.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Transport\Infrastructure;

/**
 * Stateless Origin allowlist evaluator.
 *
 * Decision order:
 *   1. No Origin header  → allow (server-to-server: bridge, curl)
 *   2. Origin host == request host  → allow (same-site browser)
 *   3. Origin host is a localhost loopback  → allow
 *   4. Origin matches operator allowlist (filter)  → allow
 *   5. Otherwise  → reject
 */
final class OriginValidator {

	/**
	 * Loopback host names treated as local dev.
	 *
	 * IPv6 `[::1]` arrives in Origin header without brackets at the host
	 * level after parse_url(), so we compare bare host strings.
	 */
	private const LOOPBACK_HOSTS = array( 'localhost', '127.0.0.1', '[::1]', '::1' );

	/**
	 * Decide whether the Origin header on this request is allowed.
	 *
	 * @param \WP_REST_Request<array<string, mixed>> $request The REST request.
	 * @return bool True if allowed, false if the request must be rejected.
	 */
	public static function is_allowed( \WP_REST_Request $request ): bool {
		$origin = $request->get_header( 'origin' );

		// Rule 1: no Origin → server-to-server, allow.
		if ( ! is_string( $origin ) || '' === $origin ) {
			return true;
		}

		$origin_host = self::host_from( $origin );
		if ( '' === $origin_host ) {
			// Malformed Origin header — reject.
			return false;
		}

		// Rule 2: same-site (Origin host matches request Host header).
		$request_host = self::request_host();
		if ( '' !== $request_host && strcasecmp( $origin_host, $request_host ) === 0 ) {
			return true;
		}

		// Rule 3: localhost loopback.
		if ( self::is_loopback( $origin_host ) ) {
			return true;
		}

		// Rule 4: operator-configured allowlist.
		$default_origins = array(
			home_url(),
			site_url(),
			'http://localhost',
			'http://127.0.0.1',
		);

		/**
		 * Filter the list of allowed Origin values for the MCP transport.
		 *
		 * Each entry may be a full origin (`https://example.com`) or a bare
		 * host (`example.com`). Comparison is host-only and case-insensitive.
		 *
		 * @param array              $default_origins Default allowed origins.
		 * @param \WP_REST_Request $request         Current request, for context-dependent allowlists.
		 */
		$allowed = apply_filters( 'abilities_mcp_allowed_origins', $default_origins, $request );

		if ( ! is_array( $allowed ) ) {
			return false;
		}

		foreach ( $allowed as $candidate ) {
			if ( ! is_string( $candidate ) || '' === $candidate ) {
				continue;
			}
			$candidate_host = self::host_from( $candidate );
			if ( '' !== $candidate_host && strcasecmp( $origin_host, $candidate_host ) === 0 ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Extract the lowercased host from an Origin or URL string.
	 *
	 * Accepts both `https://host:port` and bare `host` forms.
	 *
	 * @param string $value Origin or host string.
	 * @return string Lowercased host, or empty string on parse failure.
	 */
	private static function host_from( string $value ): string {
		$value = trim( $value );
		if ( '' === $value ) {
			return '';
		}

		// Bare host (no scheme) — accept as-is if it looks host-shaped.
		if ( strpos( $value, '://' ) === false ) {
			return strtolower( $value );
		}

		$host = wp_parse_url( $value, PHP_URL_HOST );
		if ( ! is_string( $host ) || '' === $host ) {
			return '';
		}

		return strtolower( $host );
	}

	/**
	 * Resolve the request's own host from server vars.
	 *
	 * @return string Lowercased host or empty string.
	 */
	private static function request_host(): string {
		if ( ! isset( $_SERVER['HTTP_HOST'] ) || ! is_string( $_SERVER['HTTP_HOST'] ) ) {
			return '';
		}
		$host = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );

		// Strip optional port.
		$colon = strrpos( $host, ':' );
		if ( false !== $colon && false === strpos( $host, ']' ) ) {
			$host = substr( $host, 0, $colon );
		}

		return strtolower( $host );
	}

	/**
	 * Test whether a host is a loopback.
	 *
	 * @param string $host Lowercased host string.
	 * @return bool
	 */
	private static function is_loopback( string $host ): bool {
		return in_array( $host, self::LOOPBACK_HOSTS, true );
	}

	/**
	 * Echo the Origin header value back if (and only if) it is allowed.
	 *
	 * Used to populate `Access-Control-Allow-Origin` on responses. Returns
	 * empty string when the header should be omitted entirely (wildcard `*`
	 * is incompatible with Allow-Credentials: true and is never used).
	 *
	 * @param \WP_REST_Request<array<string, mixed>> $request The REST request.
	 * @return string The exact Origin string to echo, or '' to omit the header.
	 */
	public static function echoable_origin( \WP_REST_Request $request ): string {
		$origin = $request->get_header( 'origin' );
		if ( ! is_string( $origin ) || '' === $origin ) {
			return '';
		}
		return self::is_allowed( $request ) ? $origin : '';
	}
}
