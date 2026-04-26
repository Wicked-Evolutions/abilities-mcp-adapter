<?php

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Transport\Infrastructure;

use WickedEvolutions\McpAdapter\Transport\Infrastructure\OriginValidator;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class OriginValidatorTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['wp_test_home_url'] = 'https://example.com';
		$GLOBALS['wp_test_site_url'] = 'https://example.com';
		$_SERVER['HTTP_HOST']        = 'example.com';
		unset( $GLOBALS['wp_test_filters']['abilities_mcp_allowed_origins'] );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['wp_test_filters']['abilities_mcp_allowed_origins'] );
		parent::tearDown();
	}

	private function request_with_origin( ?string $origin ): \WP_REST_Request {
		$req = new \WP_REST_Request();
		if ( null !== $origin ) {
			$req->set_header( 'origin', $origin );
		}
		return $req;
	}

	// ── Rule 1: no Origin → server-to-server, allow ──

	public function test_no_origin_header_is_allowed(): void {
		$this->assertTrue( OriginValidator::is_allowed( $this->request_with_origin( null ) ) );
	}

	public function test_empty_origin_header_is_allowed(): void {
		$this->assertTrue( OriginValidator::is_allowed( $this->request_with_origin( '' ) ) );
	}

	// ── Rule 2: same-site (Origin host matches request Host) ──

	public function test_same_origin_browser_is_allowed(): void {
		$this->assertTrue( OriginValidator::is_allowed( $this->request_with_origin( 'https://example.com' ) ) );
	}

	public function test_same_origin_with_port_in_request_host_is_allowed(): void {
		$_SERVER['HTTP_HOST'] = 'example.com:8443';
		$this->assertTrue( OriginValidator::is_allowed( $this->request_with_origin( 'https://example.com' ) ) );
	}

	public function test_same_origin_case_insensitive(): void {
		$this->assertTrue( OriginValidator::is_allowed( $this->request_with_origin( 'https://EXAMPLE.com' ) ) );
	}

	// ── Rule 3: localhost loopbacks ──

	public function test_localhost_with_port_is_allowed(): void {
		$this->assertTrue( OriginValidator::is_allowed( $this->request_with_origin( 'http://localhost:6274' ) ) );
	}

	public function test_loopback_v4_is_allowed(): void {
		$this->assertTrue( OriginValidator::is_allowed( $this->request_with_origin( 'http://127.0.0.1:8080' ) ) );
	}

	public function test_loopback_v6_is_allowed(): void {
		$this->assertTrue( OriginValidator::is_allowed( $this->request_with_origin( 'http://[::1]:6274' ) ) );
	}

	// ── Rule 4: operator allowlist via filter ──

	public function test_default_allowlist_includes_home_url(): void {
		$_SERVER['HTTP_HOST']        = 'cdn.example.net'; // not same-site
		$GLOBALS['wp_test_home_url'] = 'https://primary.example.com';
		$this->assertTrue( OriginValidator::is_allowed( $this->request_with_origin( 'https://primary.example.com' ) ) );
	}

	public function test_filter_can_add_extra_allowed_origin(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$GLOBALS['wp_test_filters']['abilities_mcp_allowed_origins'] = static function ( $defaults ) {
			$defaults[] = 'https://trusted-partner.example.org';
			return $defaults;
		};
		$this->assertTrue( OriginValidator::is_allowed( $this->request_with_origin( 'https://trusted-partner.example.org' ) ) );
	}

	public function test_filter_can_revoke_default_allowlist(): void {
		// Filter returns empty array; only same-site / loopback rules remain.
		$GLOBALS['wp_test_filters']['abilities_mcp_allowed_origins'] = static function () {
			return array();
		};
		$_SERVER['HTTP_HOST']        = 'example.com';
		$GLOBALS['wp_test_home_url'] = 'https://other.example.com';
		// Origin matches the default home_url, but the filter dropped it.
		$this->assertFalse( OriginValidator::is_allowed( $this->request_with_origin( 'https://other.example.com' ) ) );
	}

	public function test_non_array_filter_return_rejects(): void {
		$GLOBALS['wp_test_filters']['abilities_mcp_allowed_origins'] = static function () {
			return 'not-an-array';
		};
		$_SERVER['HTTP_HOST'] = 'example.com';
		$this->assertFalse( OriginValidator::is_allowed( $this->request_with_origin( 'https://attacker.example' ) ) );
	}

	// ── Rule 5: rejection ──

	public function test_evil_domain_is_rejected(): void {
		$this->assertFalse( OriginValidator::is_allowed( $this->request_with_origin( 'https://attacker.example' ) ) );
	}

	public function test_subdomain_of_allowed_host_is_rejected(): void {
		// example.com is allowed, but evil.example.com is NOT — host comparison is exact.
		$this->assertFalse( OriginValidator::is_allowed( $this->request_with_origin( 'https://evil.example.com' ) ) );
	}

	public function test_malformed_origin_is_rejected(): void {
		// Scheme-only string, no host.
		$this->assertFalse( OriginValidator::is_allowed( $this->request_with_origin( 'https://' ) ) );
	}

	// ── echoable_origin() ──

	public function test_echoable_origin_returns_exact_string_when_allowed(): void {
		$this->assertSame(
			'http://localhost:6274',
			OriginValidator::echoable_origin( $this->request_with_origin( 'http://localhost:6274' ) )
		);
	}

	public function test_echoable_origin_returns_empty_when_disallowed(): void {
		$this->assertSame(
			'',
			OriginValidator::echoable_origin( $this->request_with_origin( 'https://attacker.example' ) )
		);
	}

	public function test_echoable_origin_returns_empty_when_no_origin(): void {
		$this->assertSame( '', OriginValidator::echoable_origin( $this->request_with_origin( null ) ) );
	}

	public function test_wildcard_origin_string_is_never_echoed(): void {
		// Defensive: even if some upstream tampers and sends `*`, we never echo it.
		$this->assertSame( '', OriginValidator::echoable_origin( $this->request_with_origin( '*' ) ) );
	}
}
