<?php
/**
 * Tests for ClientRegistry::redirect_uri_valid().
 *
 * DB-dependent methods (register, find, revoke) are integration-only.
 * redirect_uri_valid is pure logic and fully unit-testable.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\ClientRegistry;

final class ClientRegistryTest extends TestCase {

	/** Build a minimal client stub with serialized redirect_uris. */
	private function client( array $uris ): object {
		$obj                = new \stdClass();
		$obj->redirect_uris = json_encode( $uris );
		return $obj;
	}

	// --- Loopback URIs (RFC 8252 §7.3) ---

	public function test_loopback_http_127_accepted(): void {
		$client = $this->client( [ 'http://127.0.0.1/callback' ] );
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $client, 'http://127.0.0.1/callback' ) );
	}

	public function test_loopback_with_different_port_accepted(): void {
		// OAuth 2.1 §10.3.3: loopback port must be ignored.
		$client = $this->client( [ 'http://127.0.0.1/callback' ] );
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $client, 'http://127.0.0.1:9876/callback' ) );
	}

	public function test_loopback_localhost_rejected(): void {
		// localhost is not a valid loopback in this context — use 127.0.0.1.
		$client = $this->client( [ 'http://localhost/callback' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $client, 'http://localhost/callback' ) );
	}

	public function test_loopback_path_mismatch_rejected(): void {
		$client = $this->client( [ 'http://127.0.0.1/callback' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $client, 'http://127.0.0.1/other' ) );
	}

	// --- Non-loopback URIs: must be HTTPS, exact match ---

	public function test_https_non_loopback_exact_match_accepted(): void {
		$client = $this->client( [ 'https://bridge.example.com/oauth/callback' ] );
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $client, 'https://bridge.example.com/oauth/callback' ) );
	}

	public function test_https_non_loopback_path_mismatch_rejected(): void {
		$client = $this->client( [ 'https://bridge.example.com/oauth/callback' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $client, 'https://bridge.example.com/different' ) );
	}

	public function test_http_non_loopback_rejected(): void {
		$client = $this->client( [ 'https://bridge.example.com/callback' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $client, 'http://bridge.example.com/callback' ) );
	}

	public function test_uri_not_in_registered_list_rejected(): void {
		$client = $this->client( [ 'https://allowed.example.com/callback' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $client, 'https://attacker.example.com/callback' ) );
	}

	public function test_empty_registered_list_rejected(): void {
		$client = $this->client( [] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $client, 'https://example.com/callback' ) );
	}

	public function test_empty_requested_uri_rejected(): void {
		$client = $this->client( [ 'https://example.com/callback' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $client, '' ) );
	}

	public function test_ipv6_loopback_accepted(): void {
		$client = $this->client( [ 'http://[::1]/callback' ] );
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $client, 'http://[::1]/callback' ) );
	}

	public function test_multiple_registered_uris_finds_correct_one(): void {
		$client = $this->client( [
			'https://primary.example.com/callback',
			'http://127.0.0.1/callback',
		] );
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $client, 'https://primary.example.com/callback' ) );
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $client, 'http://127.0.0.1/callback' ) );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $client, 'https://other.example.com/callback' ) );
	}
}
