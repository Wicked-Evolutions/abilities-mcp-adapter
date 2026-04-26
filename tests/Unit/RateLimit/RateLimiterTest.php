<?php
/**
 * Tests for RateLimiter.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

namespace WickedEvolutions\McpAdapter\Tests\Unit\RateLimit;

use WickedEvolutions\McpAdapter\RateLimit\CounterStore;
use WickedEvolutions\McpAdapter\RateLimit\RateLimiter;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class RateLimiterTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		$GLOBALS['wp_test_transients']    = array();
		$GLOBALS['wp_test_object_cache']  = array();
		$GLOBALS['wp_test_using_ext_cache'] = false;
		remove_all_filters();
	}

	private function make_limiter(): RateLimiter {
		// Force transient backend so tests don't depend on object cache.
		return new RateLimiter( new CounterStore( CounterStore::BACKEND_TRANSIENT ) );
	}

	// --- IP window ---

	public function test_61st_request_from_one_ip_returns_deny(): void {
		$limiter = $this->make_limiter();
		for ( $i = 1; $i <= 60; $i++ ) {
			$this->assertSame( 'allow', $limiter->check( 'tools/list', '203.0.113.5', 0, 'srv|1' )[0], "request $i should be allowed" );
		}
		$verdict = $limiter->check( 'tools/list', '203.0.113.5', 0, 'srv|1' );
		$this->assertSame( 'deny', $verdict[0] );
		$this->assertSame( RateLimiter::DIMENSION_IP, $verdict[3] );
		$this->assertSame( 60, $verdict[4] );
		$this->assertSame( 60, $verdict[5] );
		$this->assertGreaterThanOrEqual( 1, $verdict[1] );
	}

	public function test_two_ips_each_50_both_succeed(): void {
		$limiter = $this->make_limiter();
		for ( $i = 1; $i <= 50; $i++ ) {
			$this->assertSame( 'allow', $limiter->check( 'tools/list', '198.51.100.1', 0, 'srv|1' )[0] );
			$this->assertSame( 'allow', $limiter->check( 'tools/list', '198.51.100.2', 0, 'srv|1' )[0] );
		}
	}

	// --- User window ---

	public function test_one_user_two_ips_trips_user_window(): void {
		$limiter = $this->make_limiter();
		for ( $i = 1; $i <= 50; $i++ ) {
			$this->assertSame( 'allow', $limiter->check( 'tools/list', '198.51.100.1', 7, 'srv|1' )[0] );
		}
		// Second IP, same user — first 10 fine.
		for ( $i = 1; $i <= 10; $i++ ) {
			$this->assertSame( 'allow', $limiter->check( 'tools/list', '198.51.100.2', 7, 'srv|1' )[0] );
		}
		// 11th hits the user window (user count = 61).
		$verdict = $limiter->check( 'tools/list', '198.51.100.2', 7, 'srv|1' );
		$this->assertSame( 'deny', $verdict[0] );
		$this->assertSame( RateLimiter::DIMENSION_USER, $verdict[3] );
	}

	// --- Per-site isolation ---

	public function test_per_site_keys_are_independent(): void {
		$limiter = $this->make_limiter();
		for ( $i = 1; $i <= 60; $i++ ) {
			$this->assertSame( 'allow', $limiter->check( 'tools/list', '198.51.100.1', 0, 'site-a|1' )[0] );
		}
		// Site A is now full, but site B has its own budget.
		$this->assertSame( 'allow', $limiter->check( 'tools/list', '198.51.100.1', 0, 'site-b|1' )[0] );
	}

	// --- Filter hook ---

	public function test_filter_allow_short_circuits_default(): void {
		$limiter = $this->make_limiter();
		add_filter( 'mcp_adapter_request_rate_limit', static function () {
			return array( 'allow' );
		}, 10, 3 );
		// Even after 100 calls, never denied.
		for ( $i = 1; $i <= 100; $i++ ) {
			$this->assertSame( 'allow', $limiter->check( 'tools/list', '198.51.100.1', 0, 'srv|1' )[0] );
		}
	}

	public function test_filter_deny_short_circuits_default(): void {
		$limiter = $this->make_limiter();
		add_filter( 'mcp_adapter_request_rate_limit', static function () {
			return array( 'deny', 30, 'custom_reason' );
		}, 10, 3 );
		$verdict = $limiter->check( 'tools/list', '198.51.100.1', 0, 'srv|1' );
		$this->assertSame( 'deny', $verdict[0] );
		$this->assertSame( 30, $verdict[1] );
		$this->assertSame( 'custom_reason', $verdict[2] );
	}

	public function test_filter_returning_null_falls_through(): void {
		$limiter = $this->make_limiter();
		add_filter( 'mcp_adapter_request_rate_limit', static function () {
			return null;
		}, 10, 3 );
		$this->assertSame( 'allow', $limiter->check( 'tools/list', '198.51.100.1', 0, 'srv|1' )[0] );
	}

	// --- Configurable limits ---

	public function test_filter_lowers_ip_limit(): void {
		$limiter = $this->make_limiter();
		add_filter( 'abilities_mcp_rate_limit_per_minute_ip', static function () {
			return 3;
		} );
		for ( $i = 1; $i <= 3; $i++ ) {
			$this->assertSame( 'allow', $limiter->check( 'tools/list', '198.51.100.1', 0, 'srv|1' )[0] );
		}
		$this->assertSame( 'deny', $limiter->check( 'tools/list', '198.51.100.1', 0, 'srv|1' )[0] );
	}

	// --- Empty IP handling ---

	public function test_empty_ip_skips_ip_window(): void {
		$limiter = $this->make_limiter();
		// Authenticated user with no resolvable IP — only user window applies.
		for ( $i = 1; $i <= 60; $i++ ) {
			$this->assertSame( 'allow', $limiter->check( 'tools/list', '', 9, 'srv|1' )[0] );
		}
		$verdict = $limiter->check( 'tools/list', '', 9, 'srv|1' );
		$this->assertSame( 'deny', $verdict[0] );
		$this->assertSame( RateLimiter::DIMENSION_USER, $verdict[3] );
	}

	// --- Knowledge Layer Initial Read regression ---

	public function test_knowledge_layer_initial_read_does_not_trip(): void {
		$limiter = $this->make_limiter();
		// ~4 calls in tight succession.
		for ( $i = 1; $i <= 4; $i++ ) {
			$this->assertSame( 'allow', $limiter->check( 'tools/call', '198.51.100.1', 5, 'srv|1' )[0] );
		}
	}
}
