<?php
/**
 * Tests for HttpTransport's PII-safe boundary-tag helpers.
 *
 * Covers the IP truncation and enum coercion that gate raw values
 * out of `boundary.auth.denied` events.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Transport;

use WickedEvolutions\McpAdapter\Transport\HttpTransport;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class HttpTransportTest extends TestCase {

	public function test_truncate_ipv4_to_slash_24(): void {
		$this->assertSame( '203.0.113.0/24', HttpTransport::truncate_ip_for_log( '203.0.113.5' ) );
	}

	public function test_truncate_ipv4_loopback(): void {
		$this->assertSame( '127.0.0.0/24', HttpTransport::truncate_ip_for_log( '127.0.0.1' ) );
	}

	public function test_truncate_ipv6_to_slash_48(): void {
		$this->assertSame( '2606:4700:1234::/48', HttpTransport::truncate_ip_for_log( '2606:4700:1234:5678::1' ) );
	}

	public function test_truncate_invalid_returns_empty(): void {
		$this->assertSame( '', HttpTransport::truncate_ip_for_log( 'not-an-ip' ) );
		$this->assertSame( '', HttpTransport::truncate_ip_for_log( '' ) );
	}

	public function test_auth_deny_enum_constants_are_distinct(): void {
		$reasons = array(
			HttpTransport::AUTH_DENY_INVALID_CREDENTIALS,
			HttpTransport::AUTH_DENY_MISSING_ORIGIN,
			HttpTransport::AUTH_DENY_EXPIRED_TOKEN,
			HttpTransport::AUTH_DENY_PERMISSION_DENIED,
			HttpTransport::AUTH_DENY_DISALLOWED_ORIGIN,
			HttpTransport::AUTH_DENY_MALFORMED_REQUEST,
			HttpTransport::AUTH_DENY_UNKNOWN,
		);
		$this->assertCount( 7, array_unique( $reasons ) );
		// Sanity-check the values are the strings the brief asked for —
		// these are the contract third-party listeners will key on.
		$this->assertSame( 'invalid_credentials', HttpTransport::AUTH_DENY_INVALID_CREDENTIALS );
		$this->assertSame( 'missing_origin', HttpTransport::AUTH_DENY_MISSING_ORIGIN );
		$this->assertSame( 'expired_token', HttpTransport::AUTH_DENY_EXPIRED_TOKEN );
		$this->assertSame( 'permission_denied', HttpTransport::AUTH_DENY_PERMISSION_DENIED );
		$this->assertSame( 'disallowed_origin', HttpTransport::AUTH_DENY_DISALLOWED_ORIGIN );
		$this->assertSame( 'malformed_request', HttpTransport::AUTH_DENY_MALFORMED_REQUEST );
		$this->assertSame( 'unknown', HttpTransport::AUTH_DENY_UNKNOWN );
	}
}
