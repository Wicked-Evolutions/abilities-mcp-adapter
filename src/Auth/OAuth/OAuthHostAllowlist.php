<?php
/**
 * HTTP_HOST allowlist for OAuth pre-WP route interception.
 *
 * An attacker can set any Host header they like. Before serving discovery
 * documents or consent pages, we validate HTTP_HOST against the known set
 * of WordPress site domains. Unknown hosts get a 404 + boundary log entry.
 *
 * Built at plugins_loaded from $wpdb->blogs (multisite) or home_url() (single).
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

/**
 * Allowlist of valid HTTP_HOST values for this WordPress installation.
 */
final class OAuthHostAllowlist {

	private static ?array $hosts = null;

	/**
	 * Build the allowlist. Called once at plugins_loaded.
	 * Idempotent — safe to call multiple times.
	 */
	public static function build(): void {
		if ( self::$hosts !== null ) {
			return;
		}

		global $wpdb;

		if ( function_exists( 'is_multisite' ) && is_multisite() && isset( $wpdb->blogs ) ) {
			$rows = $wpdb->get_results(
				"SELECT domain FROM {$wpdb->blogs} WHERE deleted = 0 AND archived = 0 AND spam = 0",
				ARRAY_A
			);
			self::$hosts = array_map( 'strtolower', array_column( $rows ?: [], 'domain' ) );
		}

		// Always include the single-site home domain as a fallback.
		if ( function_exists( 'home_url' ) ) {
			$parsed = function_exists( 'wp_parse_url' )
				? wp_parse_url( home_url(), PHP_URL_HOST )
				: parse_url( home_url(), PHP_URL_HOST );
			if ( $parsed ) {
				self::$hosts[] = strtolower( (string) $parsed );
			}
		}

		self::$hosts = array_values( array_unique( self::$hosts ?? [] ) );
	}

	/**
	 * Inject a custom allowlist (for tests or WP-less environments).
	 *
	 * @param array $hosts Lowercase domain strings.
	 */
	public static function override( array $hosts ): void {
		self::$hosts = array_map( 'strtolower', $hosts );
	}

	/** Reset (for tests). */
	public static function reset(): void {
		self::$hosts = null;
	}

	/**
	 * Whether a Host value is in the allowlist.
	 *
	 * @param string $host Raw HTTP_HOST value (may include port).
	 */
	public static function is_allowed( string $host ): bool {
		if ( self::$hosts === null ) {
			self::build();
		}
		// Strip port from HTTP_HOST if present (e.g. "example.com:8080").
		$host = strtolower( explode( ':', $host )[0] );
		return in_array( $host, self::$hosts, true );
	}
}
