<?php
/**
 * OAuth client registry — Dynamic Client Registration (RFC 7591).
 *
 * Manages kl_oauth_clients table: registration, lookup, revocation.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

/**
 * CRUD operations for registered OAuth clients.
 */
final class ClientRegistry {

	/** @return string */
	private static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'kl_oauth_clients';
	}

	/**
	 * Register a new client via DCR.
	 *
	 * @param string $client_name     Human-readable name.
	 * @param array  $redirect_uris   Validated redirect URIs.
	 * @param string $scope           Space-separated requested scopes.
	 * @param string $software_id     Stable software product identifier.
	 * @param string $software_version Bridge version string.
	 * @param string $registered_ip   IP address of the registering agent.
	 * @return string Opaque client_id (UUID).
	 */
	public static function register(
		string $client_name,
		array  $redirect_uris,
		string $scope,
		string $software_id,
		string $software_version,
		string $registered_ip
	): string {
		global $wpdb;

		$client_id = wp_generate_uuid4();

		$wpdb->insert(
			self::table(),
			[
				'client_id'        => $client_id,
				'client_name'      => mb_substr( $client_name, 0, 255 ),
				'redirect_uris'    => wp_json_encode( $redirect_uris ),
				'software_id'      => mb_substr( $software_id, 0, 128 ),
				'software_version' => mb_substr( $software_version, 0, 32 ),
				'scopes'           => $scope,
				'registered_ip'    => mb_substr( $registered_ip, 0, 45 ),
				'registered_at'    => gmdate( 'Y-m-d H:i:s' ),
			],
			[ '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ]
		);

		return $client_id;
	}

	/**
	 * Look up a client by client_id. Returns null if not found or revoked.
	 *
	 * @param string $client_id
	 * @return object|null Row from kl_oauth_clients.
	 */
	public static function find( string $client_id ): ?object {
		global $wpdb;

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM `' . self::table() . '` WHERE client_id = %s AND revoked_at IS NULL',
				$client_id
			)
		);

		return $row ?: null;
	}

	/**
	 * Validate that a redirect_uri was registered for this client.
	 *
	 * Loopback URIs match ignoring port (OAuth 2.1 §10.3.3 / RFC 8252 §7.3).
	 * Loopback query strings are compared *normalized* (H-9): same key/value
	 * pairs in any order, with consistent percent-encoding, are treated as
	 * equivalent. Path is still compared strictly — `/callback` and
	 * `/callback/` are distinct because most native HTTP servers route them
	 * to different handlers, and normalising would mask client misconfig.
	 *
	 * Non-loopback URIs require exact string match (H.1.2 — exact-match is
	 * the safer rule for redirect URIs that may carry tokens/codes through
	 * proxies/CDNs/browser cache layers).
	 *
	 * Fragments are rejected on the candidate side (RFC 6749 §3.1.2: "The
	 * endpoint URI MUST NOT include a fragment component."). A registered
	 * URI that itself contains a fragment is also rejected as a non-match,
	 * but the storage side already treats fragments as invalid input via
	 * the registration validator — this is belt-and-suspenders.
	 *
	 * @param object $client   Row from find().
	 * @param string $uri      URI to validate.
	 * @return bool
	 */
	public static function redirect_uri_valid( object $client, string $uri ): bool {
		$registered = json_decode( $client->redirect_uris, true ) ?: [];

		if ( ! $uri ) {
			return false;
		}

		$parsed_candidate = parse_url( $uri );
		if ( ! is_array( $parsed_candidate ) ) {
			return false;
		}

		// RFC 6749 §3.1.2: redirect_uri MUST NOT include a fragment (H-9).
		if ( isset( $parsed_candidate['fragment'] ) ) {
			return false;
		}

		$candidate_host   = $parsed_candidate['host'] ?? '';
		$candidate_scheme = $parsed_candidate['scheme'] ?? '';
		$candidate_path   = $parsed_candidate['path'] ?? '/';
		$candidate_query  = $parsed_candidate['query'] ?? '';
		// parse_url wraps IPv6 literals in brackets: '[::1]' not '::1'.
		$candidate_host_clean = trim( $candidate_host, '[]' );
		$is_loopback          = in_array( $candidate_host_clean, [ '127.0.0.1', '::1' ], true );

		// Non-loopback URIs must use HTTPS (RFC 8252 §8.3).
		// Loopback URIs must use http (not https) with 127.0.0.1 or ::1 (RFC 8252 §7.3).
		if ( ! $is_loopback && $candidate_scheme !== 'https' ) {
			return false;
		}

		foreach ( $registered as $registered_uri ) {
			if ( $is_loopback && $candidate_scheme === 'http' ) {
				// Loopback: match scheme + host + path; ignore port; normalize query (H-9).
				$parsed_reg = parse_url( $registered_uri );
				if ( ! is_array( $parsed_reg ) ) {
					continue;
				}
				if ( isset( $parsed_reg['fragment'] ) ) {
					continue;
				}
				if (
					( $parsed_reg['scheme'] ?? '' ) === $candidate_scheme &&
					( $parsed_reg['host'] ?? '' ) === $candidate_host &&
					( $parsed_reg['path'] ?? '/' ) === $candidate_path &&
					self::query_normalize( $parsed_reg['query'] ?? '' ) === self::query_normalize( $candidate_query )
				) {
					return true;
				}
			} else {
				// Non-loopback: exact match required (H.1.2).
				if ( hash_equals( $registered_uri, $uri ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Normalize a query string for loopback redirect_uri comparison (H-9).
	 *
	 * - parse_str canonicalizes percent-encoding (%20 ↔ + → space) into the
	 *   key/value pairs.
	 * - ksort orders keys deterministically so ?foo=1&bar=2 ≡ ?bar=2&foo=1.
	 * - http_build_query re-encodes with PHP_QUERY_RFC3986 so the canonical
	 *   form is always %20 (never +) for spaces.
	 * - Empty query and missing query both collapse to '' via the upstream
	 *   `?? ''` default.
	 */
	private static function query_normalize( string $query ): string {
		if ( $query === '' ) {
			return '';
		}
		$parts = [];
		parse_str( $query, $parts );
		if ( ! is_array( $parts ) || $parts === [] ) {
			return '';
		}
		ksort( $parts );
		return http_build_query( $parts, '', '&', PHP_QUERY_RFC3986 );
	}

	/**
	 * Revoke a client and cascade-revoke all its tokens.
	 * All four writes happen in a single DB transaction.
	 *
	 * @param string $client_id
	 */
	public static function revoke( string $client_id ): void {
		global $wpdb;

		$wpdb->query( 'START TRANSACTION' );
		try {
			$wpdb->update( $wpdb->prefix . 'kl_oauth_tokens', [ 'revoked' => 1 ], [ 'client_id' => $client_id ], [ '%d' ], [ '%s' ] );
			$wpdb->update( $wpdb->prefix . 'kl_oauth_refresh_tokens', [ 'revoked' => 1 ], [ 'client_id' => $client_id ], [ '%d' ], [ '%s' ] );
			$wpdb->update( $wpdb->prefix . 'kl_oauth_codes', [ 'used' => 1 ], [ 'client_id' => $client_id ], [ '%d' ], [ '%s' ] );
			$wpdb->update( self::table(), [ 'revoked_at' => gmdate( 'Y-m-d H:i:s' ) ], [ 'client_id' => $client_id ], [ '%s' ], [ '%s' ] );
			$wpdb->query( 'COMMIT' );
		} catch ( \Throwable $e ) {
			$wpdb->query( 'ROLLBACK' );
			throw $e;
		}
	}

	/** Count active (non-revoked) clients for a given site. Used for site-level abuse cap. */
	public static function count_active(): int {
		global $wpdb;
		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM `' . self::table() . '` WHERE revoked_at IS NULL' );
	}

	/** Return list of active clients for the Connected Bridges UI. */
	public static function list_active( int $limit = 100, int $offset = 0 ): array {
		global $wpdb;
		return $wpdb->get_results(
			$wpdb->prepare(
				'SELECT client_id, client_name, software_id, software_version, scopes, registered_ip, registered_at
				 FROM `' . self::table() . '`
				 WHERE revoked_at IS NULL
				 ORDER BY registered_at DESC
				 LIMIT %d OFFSET %d',
				$limit,
				$offset
			)
		) ?: [];
	}
}
