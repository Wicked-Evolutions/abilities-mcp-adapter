<?php
/**
 * Per-IP rate limiter for OAuth DCR endpoint.
 *
 * Uses WordPress transients: fast, no extra infra needed.
 * Limits: 10/min, 100/hr per IP (H.3.3).
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

/**
 * Checks and records DCR rate limits per IP address.
 */
final class RateLimiter {

	private const LIMIT_PER_MINUTE = 10;
	private const LIMIT_PER_HOUR   = 100;
	private const SITE_CAP         = 1000; // Max unused clients per site before 503.

	/** Revocation rate-limit constants (M-7). Tighter than DCR: revoke is a destructive op. */
	private const REVOKE_LIMIT_PER_MINUTE = 20;
	private const REVOKE_LIMIT_PER_HOUR   = 200;

	/**
	 * Check whether the given IP is within rate limits for DCR.
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 * @return true|int True if allowed; seconds to retry-after on limit exceeded.
	 */
	public static function check_dcr( string $ip ): true|int {
		$key_min = 'abilities_oauth_dcr_rpm_' . md5( $ip );
		$key_hr  = 'abilities_oauth_dcr_rph_' . md5( $ip );

		$count_min = (int) get_transient( $key_min );
		if ( $count_min >= self::LIMIT_PER_MINUTE ) {
			return 60;
		}

		$count_hr = (int) get_transient( $key_hr );
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

		$count_min = (int) get_transient( $key_min );
		set_transient( $key_min, $count_min + 1, 60 );

		$count_hr = (int) get_transient( $key_hr );
		set_transient( $key_hr, $count_hr + 1, 3600 );
	}

	/**
	 * Check whether the given IP is within rate limits for the revoke endpoint (M-7).
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 * @return true|int True if allowed; seconds to retry-after on limit exceeded.
	 */
	public static function check_revoke( string $ip ): true|int {
		$key_min = 'abilities_oauth_rev_rpm_' . md5( $ip );
		$key_hr  = 'abilities_oauth_rev_rph_' . md5( $ip );

		$count_min = (int) get_transient( $key_min );
		if ( $count_min >= self::REVOKE_LIMIT_PER_MINUTE ) {
			return 60;
		}

		$count_hr = (int) get_transient( $key_hr );
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

		$count_min = (int) get_transient( $key_min );
		set_transient( $key_min, $count_min + 1, 60 );

		$count_hr = (int) get_transient( $key_hr );
		set_transient( $key_hr, $count_hr + 1, 3600 );
	}

	/**
	 * Check whether the site-wide unused-client cap is reached.
	 * Returns true when registration should be refused.
	 */
	public static function site_cap_reached(): bool {
		return ClientRegistry::count_active() >= self::SITE_CAP;
	}
}
