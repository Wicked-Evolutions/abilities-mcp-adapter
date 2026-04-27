<?php
/**
 * H-4: Atomic rate-limit counters — object cache path and site-transient fallback.
 *
 * Pre-fix: record_dcr used get_transient + increment + set_transient, which is
 * non-atomic and per-blog in multisite. On a network with N subsites, an attacker
 * got N independent 10/min budgets.
 *
 * After fix:
 *   - Object-cache path: wp_cache_add (atomic init) + wp_cache_incr (atomic incr).
 *   - Fallback path: get_site_transient + set_site_transient — network-wide on
 *     multisite; non-atomic but best-effort; hard site_cap_reached() is backstop.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\RateLimiter;

final class RateLimiterAtomicTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_site_transients'] = array();
		$GLOBALS['wp_test_transients']      = array();
		$GLOBALS['wp_test_object_cache']    = array();
		wp_using_ext_object_cache( false );
	}

	protected function tearDown(): void {
		$GLOBALS['wp_test_site_transients'] = array();
		$GLOBALS['wp_test_transients']      = array();
		$GLOBALS['wp_test_object_cache']    = array();
		wp_using_ext_object_cache( false );
	}

	// -------------------------------------------------------------------------
	// Site-transient path (default, no external object cache)
	// -------------------------------------------------------------------------

	public function test_site_transient_path_increments_network_wide_counter(): void {
		$ip  = '198.51.100.1';
		$key = 'abilities_oauth_dcr_rpm_' . md5( $ip );

		// No entry → check returns allowed, counter is 0.
		$this->assertTrue( RateLimiter::check_dcr( $ip ) === true );
		$this->assertSame( 0, (int) get_site_transient( $key ) );

		RateLimiter::record_dcr( $ip );
		$this->assertSame( 1, (int) get_site_transient( $key ) );

		RateLimiter::record_dcr( $ip );
		$this->assertSame( 2, (int) get_site_transient( $key ) );
	}

	public function test_site_transient_path_does_not_write_per_blog_transient(): void {
		$ip  = '198.51.100.2';
		$key = 'abilities_oauth_dcr_rpm_' . md5( $ip );

		RateLimiter::record_dcr( $ip );

		// Per-blog transient must remain untouched.
		$this->assertFalse( get_transient( $key ), 'Per-blog transient must not be written' );
	}

	public function test_site_transient_limit_blocks_at_threshold(): void {
		$ip     = '198.51.100.3';
		$key_hr = 'abilities_oauth_dcr_rph_' . md5( $ip );

		set_site_transient( $key_hr, 100, 3600 );

		$result = RateLimiter::check_dcr( $ip );
		$this->assertSame( 3600, $result, 'Hour limit must block via site_transient' );
	}

	// -------------------------------------------------------------------------
	// Object-cache path
	// -------------------------------------------------------------------------

	public function test_object_cache_path_uses_wp_cache_add_and_incr(): void {
		wp_using_ext_object_cache( true );
		$ip      = '198.51.100.10';
		$key_min = 'abilities_oauth_dcr_rpm_' . md5( $ip );

		// First record: cache is empty → wp_cache_add inits to 0, incr → 1.
		RateLimiter::record_dcr( $ip );
		$this->assertSame( 1, (int) wp_cache_get( $key_min, 'oauth_rate' ) );

		// Second record: incr → 2.
		RateLimiter::record_dcr( $ip );
		$this->assertSame( 2, (int) wp_cache_get( $key_min, 'oauth_rate' ) );
	}

	public function test_object_cache_path_check_reads_from_cache(): void {
		wp_using_ext_object_cache( true );
		$ip      = '198.51.100.11';
		$key_min = 'abilities_oauth_dcr_rpm_' . md5( $ip );

		wp_cache_set( $key_min, 10, 'oauth_rate' ); // at limit

		$result = RateLimiter::check_dcr( $ip );
		$this->assertSame( 60, $result, 'check_dcr must read from object cache' );
	}

	public function test_object_cache_path_does_not_write_site_transient(): void {
		wp_using_ext_object_cache( true );
		$ip  = '198.51.100.12';
		$key = 'abilities_oauth_dcr_rpm_' . md5( $ip );

		RateLimiter::record_dcr( $ip );

		// Site transient must remain untouched.
		$this->assertFalse( get_site_transient( $key ), 'Site transient must not be written on object-cache path' );
	}

	// -------------------------------------------------------------------------
	// Revoke uses same primitives (regression guard)
	// -------------------------------------------------------------------------

	public function test_record_revoke_increments_site_transient(): void {
		$ip  = '198.51.100.20';
		$key = 'abilities_oauth_rev_rpm_' . md5( $ip );

		RateLimiter::record_revoke( $ip );
		$this->assertSame( 1, (int) get_site_transient( $key ) );
	}

	public function test_record_revoke_uses_object_cache_when_available(): void {
		wp_using_ext_object_cache( true );
		$ip  = '198.51.100.21';
		$key = 'abilities_oauth_rev_rpm_' . md5( $ip );

		RateLimiter::record_revoke( $ip );
		$this->assertSame( 1, (int) wp_cache_get( $key, 'oauth_rate' ) );
	}
}
