<?php
/**
 * Auto-detecting counter backend for the rate limiter.
 *
 * Picks WordPress object cache when an external one is in use
 * (Redis, Memcached, etc.) and falls back to WP transients otherwise.
 * Both backends auto-expire keys at 2× the rate-limit window.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\RateLimit;

class CounterStore {

	public const BACKEND_OBJECT_CACHE = 'object_cache';
	public const BACKEND_TRANSIENT    = 'transient';

	private const CACHE_GROUP = 'abilities_mcp_rate_limit';

	private string $backend;

	public function __construct( ?string $force_backend = null ) {
		$this->backend = $force_backend ?? self::detect_backend();
	}

	/**
	 * Reported backend name.
	 */
	public function backend(): string {
		return $this->backend;
	}

	/**
	 * Increment the counter at $key, set TTL on first write, and return the new value.
	 *
	 * @param string $key
	 * @param int    $ttl_seconds
	 * @return int Counter value after increment.
	 */
	public function increment( string $key, int $ttl_seconds ): int {
		if ( self::BACKEND_OBJECT_CACHE === $this->backend ) {
			$value = function_exists( 'wp_cache_incr' ) ? wp_cache_incr( $key, 1, self::CACHE_GROUP ) : false;
			if ( false === $value || null === $value ) {
				if ( function_exists( 'wp_cache_add' ) ) {
					$added = wp_cache_add( $key, 1, self::CACHE_GROUP, $ttl_seconds );
					if ( $added ) {
						return 1;
					}
					$value = function_exists( 'wp_cache_incr' ) ? wp_cache_incr( $key, 1, self::CACHE_GROUP ) : false;
				}
			}
			if ( ! is_int( $value ) ) {
				return 1;
			}
			return $value;
		}

		// Transient fallback. Minute-precision is acceptable per spec.
		$current = function_exists( 'get_transient' ) ? get_transient( $key ) : 0;
		$current = is_numeric( $current ) ? (int) $current : 0;
		$new     = $current + 1;
		if ( function_exists( 'set_transient' ) ) {
			set_transient( $key, $new, $ttl_seconds );
		}
		return $new;
	}

	/**
	 * Read the counter without incrementing. Returns 0 if absent.
	 *
	 * @param string $key
	 * @return int
	 */
	public function get( string $key ): int {
		if ( self::BACKEND_OBJECT_CACHE === $this->backend ) {
			$value = function_exists( 'wp_cache_get' ) ? wp_cache_get( $key, self::CACHE_GROUP ) : false;
			return is_numeric( $value ) ? (int) $value : 0;
		}

		$value = function_exists( 'get_transient' ) ? get_transient( $key ) : false;
		return is_numeric( $value ) ? (int) $value : 0;
	}

	/**
	 * Choose object cache only when an external one is registered;
	 * the default in-process cache won't survive across requests.
	 */
	private static function detect_backend(): string {
		if ( function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache() ) {
			return self::BACKEND_OBJECT_CACHE;
		}
		return self::BACKEND_TRANSIENT;
	}
}
