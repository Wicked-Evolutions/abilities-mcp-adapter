<?php
/**
 * Tests for OAuthHostAllowlist.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthHostAllowlist;

final class OAuthHostAllowlistTest extends TestCase {

	protected function setUp(): void {
		OAuthHostAllowlist::reset();
	}

	public function test_override_allows_injected_host(): void {
		OAuthHostAllowlist::override( [ 'example.com', 'sub.example.com' ] );

		$this->assertTrue( OAuthHostAllowlist::is_allowed( 'example.com' ) );
		$this->assertTrue( OAuthHostAllowlist::is_allowed( 'sub.example.com' ) );
	}

	public function test_host_not_in_override_is_rejected(): void {
		OAuthHostAllowlist::override( [ 'example.com' ] );

		$this->assertFalse( OAuthHostAllowlist::is_allowed( 'evil.example.com' ) );
		$this->assertFalse( OAuthHostAllowlist::is_allowed( 'attacker.com' ) );
	}

	public function test_port_is_stripped_before_check(): void {
		OAuthHostAllowlist::override( [ 'example.com' ] );

		// HTTP_HOST may include port — strip it before comparing.
		$this->assertTrue( OAuthHostAllowlist::is_allowed( 'example.com:8080' ) );
	}

	public function test_empty_host_rejected(): void {
		OAuthHostAllowlist::override( [ 'example.com' ] );

		$this->assertFalse( OAuthHostAllowlist::is_allowed( '' ) );
	}

	public function test_reset_clears_override_and_rebuild_from_env(): void {
		// Override with an arbitrary host, then reset.
		OAuthHostAllowlist::override( [ 'custom-injected.example.com' ] );
		OAuthHostAllowlist::reset();

		// After reset, the override is gone — the injected host is no longer explicitly allowed.
		// build() will re-run (from home_url stub) but won't include custom-injected.example.com.
		$this->assertFalse( OAuthHostAllowlist::is_allowed( 'custom-injected.example.com' ) );
	}
}
