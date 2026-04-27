<?php
/**
 * Tests for DiscoveryEndpoints pure methods.
 *
 * Verifies issuer() construction and resource_url() composition.
 * Output methods (serve_*) exit, so they are integration-only.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\DiscoveryEndpoints;

final class DiscoveryEndpointsTest extends TestCase {

	protected function setUp(): void {
		// Reset server globals.
		unset( $_SERVER['HTTP_HOST'], $_SERVER['HTTPS'], $_SERVER['HTTP_X_FORWARDED_PROTO'] );
		// Ensure trust-forwarded is off by default.
		if ( defined( 'WP_OAUTH_TRUST_FORWARDED_HOST' ) ) {
			// Constant already defined — test environment may vary; we'll test what we can.
		}
	}

	public function test_issuer_uses_http_when_not_ssl(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		// is_ssl() stub returns false by default (no HTTPS server var).
		$issuer = DiscoveryEndpoints::issuer();
		$this->assertStringStartsWith( 'http://', $issuer );
		$this->assertStringContainsString( 'example.com', $issuer );
	}

	public function test_issuer_strips_port(): void {
		$_SERVER['HTTP_HOST'] = 'example.com:8080';
		$issuer = DiscoveryEndpoints::issuer();
		$this->assertStringNotContainsString( ':8080', $issuer );
		$this->assertStringContainsString( 'example.com', $issuer );
	}

	public function test_issuer_uses_https_when_ssl(): void {
		$_SERVER['HTTP_HOST'] = 'secure.example.com';
		$_SERVER['HTTPS']     = 'on';
		$issuer = DiscoveryEndpoints::issuer();
		$this->assertStringStartsWith( 'https://', $issuer );
	}

	public function test_resource_url_ends_with_mcp_path(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$resource = DiscoveryEndpoints::resource_url();
		$this->assertStringEndsWith( '/wp-json/mcp/mcp-adapter-default-server', $resource );
	}

	public function test_resource_url_contains_issuer(): void {
		$_SERVER['HTTP_HOST'] = 'mysite.example.com';
		$issuer   = DiscoveryEndpoints::issuer();
		$resource = DiscoveryEndpoints::resource_url();
		$this->assertStringStartsWith( $issuer, $resource );
	}
}
