<?php
/**
 * M-7: Per-IP rate limiting on /oauth/revoke.
 *
 * Pre-fix: the revoke endpoint had no rate limit. Now enforced at
 * 20 req/min and 200 req/hr per IP via RateLimiter::check_revoke / record_revoke.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Endpoints
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Endpoints;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints\RevokeEndpoint;
use WickedEvolutions\McpAdapter\Auth\OAuth\RateLimiter;
use WickedEvolutions\McpAdapter\Tests\TokenResponseSentinel;

final class RevokeEndpointRateLimitTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		parent::setUp();
		$this->original_wpdb           = $GLOBALS['wpdb'];
		$GLOBALS['wp_test_transients'] = array();
		$_SERVER['REMOTE_ADDR']        = '10.1.2.3';
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb']               = $this->original_wpdb;
		$GLOBALS['wp_test_transients'] = array();
		unset( $_SERVER['REMOTE_ADDR'] );
		parent::tearDown();
	}

	private function make_request( array $params ): \WP_REST_Request {
		$req = new \WP_REST_Request();
		foreach ( $params as $k => $v ) {
			$req->set_param( $k, $v );
		}
		return $req;
	}

	private function install_null_wpdb(): void {
		$GLOBALS['wpdb'] = new class {
			public string $prefix = 'wp_';
			public function prepare( $q, ...$a )     { return $q; }
			public function get_row( $q )             { return null; }
			public function get_results( $q )         { return array(); }
			public function get_var( $q )             { return null; }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null ) { return 1; }
			public function query( $sql )             { return true; }
		};
	}

	public function test_first_request_from_ip_is_allowed(): void {
		$this->install_null_wpdb();
		$req = $this->make_request( array() );

		try {
			RevokeEndpoint::handle_post( $req );
			$this->fail( 'Expected TokenResponseSentinel' );
		} catch ( TokenResponseSentinel $e ) {
			// 200 success — rate limit not triggered.
			$this->assertSame( 200, $e->status );
			$this->assertNotSame( 'rate_limit_exceeded', $e->body['error'] ?? '' );
		}
	}

	public function test_rate_limit_enforced_when_per_minute_exceeded(): void {
		$ip      = '10.1.2.3';
		$key_min = 'abilities_oauth_rev_rpm_' . md5( $ip );
		// Pre-saturate the per-minute counter at the limit.
		set_transient( $key_min, 20, 60 );

		$this->install_null_wpdb();
		$req = $this->make_request( array() );

		try {
			RevokeEndpoint::handle_post( $req );
			$this->fail( 'Expected TokenResponseSentinel' );
		} catch ( TokenResponseSentinel $e ) {
			$this->assertSame( 429, $e->status );
			$this->assertSame( 'rate_limit_exceeded', $e->body['error'] );
		}
	}

	public function test_rate_limit_enforced_when_per_hour_exceeded(): void {
		$ip     = '10.1.2.3';
		$key_hr = 'abilities_oauth_rev_rph_' . md5( $ip );
		set_transient( $key_hr, 200, 3600 );

		$this->install_null_wpdb();
		$req = $this->make_request( array() );

		try {
			RevokeEndpoint::handle_post( $req );
			$this->fail( 'Expected TokenResponseSentinel' );
		} catch ( TokenResponseSentinel $e ) {
			$this->assertSame( 429, $e->status );
			$this->assertSame( 'rate_limit_exceeded', $e->body['error'] );
		}
	}

	/** Successful requests increment both rate-limit windows. */
	public function test_successful_revoke_increments_rate_limit_counters(): void {
		$ip      = '10.1.2.3';
		$key_min = 'abilities_oauth_rev_rpm_' . md5( $ip );
		$key_hr  = 'abilities_oauth_rev_rph_' . md5( $ip );

		$this->install_null_wpdb();
		$req = $this->make_request( array() );

		try {
			RevokeEndpoint::handle_post( $req );
		} catch ( TokenResponseSentinel $e ) {
			// ignored
		}

		$this->assertSame( 1, (int) get_transient( $key_min ) );
		$this->assertSame( 1, (int) get_transient( $key_hr ) );
	}

	/** RateLimiter check_revoke and record_revoke are independent of DCR counters. */
	public function test_revoke_rate_limit_is_separate_from_dcr_rate_limit(): void {
		$ip          = '10.1.2.3';
		$dcr_key_min = 'abilities_oauth_dcr_rpm_' . md5( $ip );
		$rev_key_min = 'abilities_oauth_rev_rpm_' . md5( $ip );

		// Saturate DCR limit.
		set_transient( $dcr_key_min, 10, 60 );

		// Revoke check must still pass.
		$this->assertTrue( RateLimiter::check_revoke( $ip ) === true );

		// Record revoke — must only touch revoke keys.
		RateLimiter::record_revoke( $ip );
		$this->assertSame( 1, (int) get_transient( $rev_key_min ) );
		// DCR minute counter must be unchanged.
		$this->assertSame( 10, (int) get_transient( $dcr_key_min ) );
	}
}
