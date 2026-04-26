<?php
/**
 * Rate limiter for the /mcp boundary.
 *
 * Two parallel windows must both pass for a request to proceed:
 *   - per (remote_ip, site_id) tuple
 *   - per (user_id, site_id) tuple, when the request is authenticated
 *
 * Whichever trips first returns 429. Operators can pre-empt the
 * default with the `mcp_adapter_request_rate_limit` filter.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\RateLimit;

class RateLimiter {

	public const DIMENSION_IP   = 'ip';
	public const DIMENSION_USER = 'user';

	public const DEFAULT_LIMIT_IP     = 60;
	public const DEFAULT_LIMIT_USER   = 60;
	public const DEFAULT_WINDOW_SECS  = 60;

	private CounterStore $store;

	public function __construct( ?CounterStore $store = null ) {
		$this->store = $store ?? new CounterStore();
	}

	/**
	 * Decide whether a request should proceed.
	 *
	 * Verdict shape:
	 *   ['allow']
	 *   ['deny', $retry_after_seconds, $reason, $dimension, $limit, $window]
	 *
	 * @param string $method     JSON-RPC method name (used for filter context).
	 * @param string $client_ip  Caller IP (already resolved through trusted-proxy rules).
	 * @param int    $user_id    Authenticated user ID, or 0 when anonymous.
	 * @param string $site_key   Per-site disambiguator (server_id + blog_id).
	 * @param array  $tags       Extra tags forwarded to the filter for observability.
	 * @return array{0:string,1?:int,2?:string,3?:string,4?:int,5?:int}
	 */
	public function check( string $method, string $client_ip, int $user_id, string $site_key, array $tags = array() ): array {
		$filter_verdict = $this->run_filter( $method, $tags );
		if ( null !== $filter_verdict ) {
			return $filter_verdict;
		}

		$now    = time();
		$window = $this->config_int( 'abilities_mcp_rate_limit_window_seconds', self::DEFAULT_WINDOW_SECS, 1 );
		$limit_ip   = $this->config_int( 'abilities_mcp_rate_limit_per_minute_ip', self::DEFAULT_LIMIT_IP, 1 );
		$limit_user = $this->config_int( 'abilities_mcp_rate_limit_per_minute_user', self::DEFAULT_LIMIT_USER, 1 );

		$bucket = (int) floor( $now / $window );
		$ttl    = $window * 2;

		// IP window — only counted when we have a usable IP.
		if ( '' !== $client_ip ) {
			$ip_key   = self::ip_key( $client_ip, $site_key, $bucket );
			$ip_count = $this->store->increment( $ip_key, $ttl );
			if ( $ip_count > $limit_ip ) {
				$retry = $this->retry_after_seconds( $now, $bucket, $window );
				return array( 'deny', $retry, 'ip_limit', self::DIMENSION_IP, $limit_ip, $window );
			}
		}

		// User window — only counted for authenticated requests.
		if ( $user_id > 0 ) {
			$user_key   = self::user_key( $user_id, $site_key, $bucket );
			$user_count = $this->store->increment( $user_key, $ttl );
			if ( $user_count > $limit_user ) {
				$retry = $this->retry_after_seconds( $now, $bucket, $window );
				return array( 'deny', $retry, 'user_limit', self::DIMENSION_USER, $limit_user, $window );
			}
		}

		return array( 'allow' );
	}

	/**
	 * Counter key for the IP window. SHA-256 first 16 hex chars keep the
	 * key compact and avoid leaking raw IPs into cache key tooling.
	 *
	 * @param string $ip
	 * @param string $site_key
	 * @param int    $bucket
	 * @return string
	 */
	public static function ip_key( string $ip, string $site_key, int $bucket ): string {
		$hash = substr( hash( 'sha256', $ip . '|' . $site_key ), 0, 16 );
		return 'abmcp_rl_ip_' . $hash . '_' . $bucket;
	}

	public static function user_key( int $user_id, string $site_key, int $bucket ): string {
		$site_hash = substr( hash( 'sha256', $site_key ), 0, 8 );
		return 'abmcp_rl_u_' . $user_id . '_' . $site_hash . '_' . $bucket;
	}

	/**
	 * Build the per-site disambiguator used in counter keys.
	 *
	 * @param string $server_id
	 * @return string
	 */
	public static function build_site_key( string $server_id ): string {
		$blog_id = function_exists( 'get_current_blog_id' ) ? (int) get_current_blog_id() : 0;
		return $server_id . '|' . $blog_id;
	}

	/**
	 * @param string $method
	 * @param array  $tags
	 * @return array|null
	 */
	private function run_filter( string $method, array $tags ): ?array {
		if ( ! function_exists( 'apply_filters' ) ) {
			return null;
		}
		$verdict = apply_filters( 'mcp_adapter_request_rate_limit', null, $method, $tags );
		if ( null === $verdict ) {
			return null;
		}
		if ( ! is_array( $verdict ) || empty( $verdict[0] ) ) {
			return null;
		}
		if ( 'allow' === $verdict[0] ) {
			return array( 'allow' );
		}
		if ( 'deny' === $verdict[0] ) {
			$retry  = isset( $verdict[1] ) && is_numeric( $verdict[1] ) ? max( 0, (int) $verdict[1] ) : 1;
			$reason = isset( $verdict[2] ) && is_string( $verdict[2] ) ? $verdict[2] : 'filter_deny';
			return array( 'deny', $retry, $reason, self::DIMENSION_IP, 0, 0 );
		}
		return null;
	}

	/**
	 * Resolve a configurable integer through the matching filter,
	 * clamped to a sensible floor. Falls back to $default when the
	 * filter system isn't available (CLI / unit tests without WP).
	 */
	private function config_int( string $filter, int $default, int $min ): int {
		if ( ! function_exists( 'apply_filters' ) ) {
			return $default;
		}
		$value = apply_filters( $filter, $default );
		if ( ! is_numeric( $value ) ) {
			return $default;
		}
		return max( $min, (int) $value );
	}

	/**
	 * Seconds remaining until the current window resets — minimum 1
	 * so clients always have a positive Retry-After.
	 */
	private function retry_after_seconds( int $now, int $bucket, int $window ): int {
		$boundary = ( $bucket + 1 ) * $window;
		return max( 1, $boundary - $now );
	}
}
