<?php
/**
 * Per-IP rate limiter for OAuth DCR and revocation endpoints.
 *
 * H-4: Atomic counters — non-atomic read-increment-write replaced with:
 *   1. wp_cache_add + wp_cache_incr when an external object cache is available
 *      (Memcached/Redis: operations are atomic at the cache server level).
 *   2. get_site_transient / set_site_transient fallback for installs without
 *      an external cache. `site_transient` stores in the network sitemeta table
 *      on multisite, making the rate window network-wide rather than per-blog.
 *      Single-site installs behave identically to `transient` for this purpose.
 *
 * Limits (H.3.3):
 *   DCR:    10/min, 100/hr per IP
 *   Revoke: 20/min, 200/hr per IP  (M-7)
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

/**
 * Checks and records DCR / revocation rate limits per IP.
 */
final class RateLimiter {

	private const LIMIT_PER_MINUTE = 10;
	private const LIMIT_PER_HOUR   = 100;
	private const SITE_CAP         = 1000; // Max active clients per site before 503.

	/** Revocation rate-limit constants (M-7). */
	private const REVOKE_LIMIT_PER_MINUTE = 20;
	private const REVOKE_LIMIT_PER_HOUR   = 200;

	// -------------------------------------------------------------------------
	// DCR
	// -------------------------------------------------------------------------

	/**
	 * Check whether the given IP is within rate limits for DCR.
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 * @return true|int True if allowed; seconds to retry-after on limit exceeded.
	 */
	public static function check_dcr( string $ip ): true|int {
		$key_min = 'abilities_oauth_dcr_rpm_' . md5( $ip );
		$key_hr  = 'abilities_oauth_dcr_rph_' . md5( $ip );

		$count_min = self::counter_read( $key_min );
		if ( $count_min >= self::LIMIT_PER_MINUTE ) {
			return 60;
		}

		$count_hr = self::counter_read( $key_hr );
		if ( $count_hr >= self::LIMIT_PER_HOUR ) {
			return 3600;
		}

		return true;
	}

	/**
	 * Record a DCR registration for rate-limit tracking.
	 *
	 * @param string $ip
	 */
	public static function record_dcr( string $ip ): void {
		$key_min = 'abilities_oauth_dcr_rpm_' . md5( $ip );
		$key_hr  = 'abilities_oauth_dcr_rph_' . md5( $ip );

		self::counter_increment( $key_min, 60 );
		self::counter_increment( $key_hr, 3600 );
	}

	// -------------------------------------------------------------------------
	// Revocation (M-7)
	// -------------------------------------------------------------------------

	/**
	 * Check whether the given IP is within rate limits for the revoke endpoint (M-7).
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 * @return true|int True if allowed; seconds to retry-after on limit exceeded.
	 */
	public static function check_revoke( string $ip ): true|int {
		$key_min = 'abilities_oauth_rev_rpm_' . md5( $ip );
		$key_hr  = 'abilities_oauth_rev_rph_' . md5( $ip );

		$count_min = self::counter_read( $key_min );
		if ( $count_min >= self::REVOKE_LIMIT_PER_MINUTE ) {
			return 60;
		}

		$count_hr = self::counter_read( $key_hr );
		if ( $count_hr >= self::REVOKE_LIMIT_PER_HOUR ) {
			return 3600;
		}

		return true;
	}

	/**
	 * Record a revocation attempt for rate-limit tracking (M-7).
	 *
	 * @param string $ip
	 */
	public static function record_revoke( string $ip ): void {
		$key_min = 'abilities_oauth_rev_rpm_' . md5( $ip );
		$key_hr  = 'abilities_oauth_rev_rph_' . md5( $ip );

		self::counter_increment( $key_min, 60 );
		self::counter_increment( $key_hr, 3600 );
	}

	// -------------------------------------------------------------------------
	// Site cap
	// -------------------------------------------------------------------------

	/**
	 * Check whether the site-wide active-client cap is reached.
	 * Returns true when DCR registration should be refused.
	 */
	public static function site_cap_reached(): bool {
		return ClientRegistry::count_active() >= self::SITE_CAP;
	}

	// -------------------------------------------------------------------------
	// Atomic counter primitives (H-4)
	// -------------------------------------------------------------------------

	/**
	 * Read the current value of a rate-limit counter.
	 *
	 * @param string $key Transient/cache key.
	 * @return int Current count (0 when not set or expired).
	 */
	private static function counter_read( string $key ): int {
		if ( wp_using_ext_object_cache() ) {
			return (int) \wp_cache_get( $key, 'oauth_rate' );
		}
		return (int) \get_site_transient( $key );
	}

	/**
	 * Atomically increment a rate-limit counter, initialising it if absent.
	 *
	 * Object-cache path: wp_cache_add initialises to 0 if absent (atomic on the
	 * cache server), then wp_cache_incr increments atomically. TTL is only set
	 * on the add; subsequent increments leave the expiry untouched so the window
	 * slides from first-request, not last-request.
	 *
	 * Site-transient path: best-effort non-atomic, but network-wide on multisite.
	 * Full atomicity on this path requires a mutex or DB-level CAS — not worth the
	 * complexity for a best-effort rate limit on single-site installs. Under high
	 * concurrency a few extra requests may slip through per window; the hard
	 * site_cap_reached() check is the backstop.
	 *
	 * @param string $key Transient/cache key.
	 * @param int    $ttl Window TTL in seconds (60 or 3600).
	 */
	private static function counter_increment( string $key, int $ttl ): void {
		if ( wp_using_ext_object_cache() ) {
			// wp_cache_add is a no-op if the key already exists (atomic init).
			\wp_cache_add( $key, 0, 'oauth_rate', $ttl );
			\wp_cache_incr( $key, 1, 'oauth_rate' );
			return;
		}

		// Site-transient fallback: network-wide on multisite.
		$current = (int) \get_site_transient( $key );
		\set_site_transient( $key, $current + 1, $ttl );
	}
}
