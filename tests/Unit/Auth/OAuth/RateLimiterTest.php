<?php
/**
 * Tests for RateLimiter (DCR rate limiting).
 *
 * Uses the in-memory transient stub from bootstrap.php.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\RateLimiter;

final class RateLimiterTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_transients'] = [];
		$GLOBALS['wp_test_options']    = [];
	}

	public function test_first_request_from_ip_is_allowed(): void {
		$result = RateLimiter::check_dcr( '203.0.113.5' );
		$this->assertTrue( $result );
	}

	public function test_after_record_second_request_still_allowed_within_limit(): void {
		$ip = '203.0.113.10';
		RateLimiter::record_dcr( $ip );
		$result = RateLimiter::check_dcr( $ip );
		$this->assertTrue( $result );
	}

	public function test_record_increments_both_windows(): void {
		$ip      = '203.0.113.20';
		$key_min = 'abilities_oauth_dcr_rpm_' . md5( $ip );
		$key_hr  = 'abilities_oauth_dcr_rph_' . md5( $ip );

		RateLimiter::record_dcr( $ip );

		$this->assertSame( 1, (int) get_transient( $key_min ) );
		$this->assertSame( 1, (int) get_transient( $key_hr ) );
	}

	public function test_exceeded_hour_limit_returns_3600(): void {
		$ip = '203.0.113.30';
		$key_hr = 'abilities_oauth_dcr_rph_' . md5( $ip );
		set_transient( $key_hr, 100, 3600 ); // exactly at hourly limit

		$result = RateLimiter::check_dcr( $ip );
		$this->assertSame( 3600, $result );
	}

	public function test_exceeded_minute_limit_returns_60(): void {
		$ip = '203.0.113.40';
		$key_min = 'abilities_oauth_dcr_rpm_' . md5( $ip );
		set_transient( $key_min, 10, 60 ); // exactly at per-minute limit

		$result = RateLimiter::check_dcr( $ip );
		$this->assertSame( 60, $result );
	}
}
