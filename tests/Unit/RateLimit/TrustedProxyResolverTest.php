<?php
/**
 * Tests for TrustedProxyResolver.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

namespace WickedEvolutions\McpAdapter\Tests\Unit\RateLimit;

use WickedEvolutions\McpAdapter\RateLimit\TrustedProxyResolver;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class TrustedProxyResolverTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		$GLOBALS['wp_test_options']    = array();
		$GLOBALS['wp_test_transients'] = array();
		remove_all_filters();
	}

	// --- IP detection rules ---

	public function test_default_falls_back_to_remote_addr(): void {
		$server = array(
			'REMOTE_ADDR'          => '203.0.113.5',
			'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
		);
		$this->assertSame( '203.0.113.5', TrustedProxyResolver::resolve( $server ) );
	}

	public function test_default_ignores_cf_connecting_ip(): void {
		$server = array(
			'REMOTE_ADDR'            => '203.0.113.5',
			'HTTP_CF_CONNECTING_IP'  => '1.2.3.4',
		);
		$this->assertSame( '203.0.113.5', TrustedProxyResolver::resolve( $server ) );
	}

	public function test_cloudflare_preset_honors_cf_header_when_remote_addr_is_cloudflare(): void {
		TrustedProxyResolver::update_settings( array(
			'enabled' => true,
			'mode'    => TrustedProxyResolver::MODE_CLOUDFLARE,
		) );
		// 173.245.48.0/20 is bundled.
		$server = array(
			'REMOTE_ADDR'            => '173.245.48.10',
			'HTTP_CF_CONNECTING_IP'  => '1.2.3.4',
		);
		$this->assertSame( '1.2.3.4', TrustedProxyResolver::resolve( $server ) );
	}

	public function test_cloudflare_preset_ignores_cf_header_when_remote_addr_is_not_cloudflare(): void {
		TrustedProxyResolver::update_settings( array(
			'enabled' => true,
			'mode'    => TrustedProxyResolver::MODE_CLOUDFLARE,
		) );
		$server = array(
			'REMOTE_ADDR'            => '203.0.113.5',
			'HTTP_CF_CONNECTING_IP'  => '1.2.3.4',
		);
		$this->assertSame( '203.0.113.5', TrustedProxyResolver::resolve( $server ) );
	}

	public function test_custom_allowlist_honors_xff_when_remote_addr_matches(): void {
		TrustedProxyResolver::update_settings( array(
			'enabled'   => true,
			'mode'      => TrustedProxyResolver::MODE_CUSTOM_LIST,
			'allowlist' => array( '10.0.0.0/8' ),
		) );
		$server = array(
			'REMOTE_ADDR'          => '10.1.2.3',
			'HTTP_X_FORWARDED_FOR' => '198.51.100.7, 10.0.0.1',
		);
		$this->assertSame( '198.51.100.7', TrustedProxyResolver::resolve( $server ) );
	}

	public function test_custom_allowlist_ignores_xff_when_remote_addr_does_not_match(): void {
		TrustedProxyResolver::update_settings( array(
			'enabled'   => true,
			'mode'      => TrustedProxyResolver::MODE_CUSTOM_LIST,
			'allowlist' => array( '10.0.0.0/8' ),
		) );
		$server = array(
			'REMOTE_ADDR'          => '203.0.113.5',
			'HTTP_X_FORWARDED_FOR' => '198.51.100.7',
		);
		$this->assertSame( '203.0.113.5', TrustedProxyResolver::resolve( $server ) );
	}

	public function test_invalid_remote_addr_returns_empty(): void {
		$server = array( 'REMOTE_ADDR' => 'not-an-ip' );
		$this->assertSame( '', TrustedProxyResolver::resolve( $server ) );
	}

	public function test_loopback_treated_as_normal(): void {
		$server = array( 'REMOTE_ADDR' => '127.0.0.1' );
		$this->assertSame( '127.0.0.1', TrustedProxyResolver::resolve( $server ) );
	}

	// --- CIDR membership ---

	public function test_ip_in_cidr_v4(): void {
		$this->assertTrue( TrustedProxyResolver::ip_in_cidr( '173.245.48.10', '173.245.48.0/20' ) );
		$this->assertFalse( TrustedProxyResolver::ip_in_cidr( '203.0.113.5', '173.245.48.0/20' ) );
	}

	public function test_ip_in_cidr_v6(): void {
		$this->assertTrue( TrustedProxyResolver::ip_in_cidr( '2606:4700::1', '2606:4700::/32' ) );
		$this->assertFalse( TrustedProxyResolver::ip_in_cidr( '2001:db8::1', '2606:4700::/32' ) );
	}

	public function test_ip_in_cidr_bare_ip(): void {
		$this->assertTrue( TrustedProxyResolver::ip_in_cidr( '10.0.0.1', '10.0.0.1' ) );
		$this->assertFalse( TrustedProxyResolver::ip_in_cidr( '10.0.0.2', '10.0.0.1' ) );
	}

	public function test_ip_in_cidr_address_family_mismatch(): void {
		$this->assertFalse( TrustedProxyResolver::ip_in_cidr( '10.0.0.1', '2606:4700::/32' ) );
	}

	public function test_is_valid_cidr(): void {
		$this->assertTrue( TrustedProxyResolver::is_valid_cidr( '10.0.0.0/8' ) );
		$this->assertTrue( TrustedProxyResolver::is_valid_cidr( '2606:4700::/32' ) );
		$this->assertTrue( TrustedProxyResolver::is_valid_cidr( '203.0.113.5' ) );
		$this->assertFalse( TrustedProxyResolver::is_valid_cidr( 'not-an-ip' ) );
		$this->assertFalse( TrustedProxyResolver::is_valid_cidr( '10.0.0.0/40' ) );
		$this->assertFalse( TrustedProxyResolver::is_valid_cidr( '' ) );
	}

	// --- IP truncation for log ---

	public function test_truncate_ipv4(): void {
		$this->assertSame( '203.0.113.0/24', TrustedProxyResolver::truncate_for_log( '203.0.113.5' ) );
	}

	public function test_truncate_ipv6(): void {
		$truncated = TrustedProxyResolver::truncate_for_log( '2606:4700:1234:5678::1' );
		$this->assertSame( '2606:4700:1234::/48', $truncated );
	}

	public function test_truncate_invalid_returns_empty(): void {
		$this->assertSame( '', TrustedProxyResolver::truncate_for_log( 'not-an-ip' ) );
		$this->assertSame( '', TrustedProxyResolver::truncate_for_log( '' ) );
	}

	// --- Cloudflare cache bootstrapping ---

	public function test_cloudflare_ips_populate_from_bundled_on_first_call(): void {
		$ips = TrustedProxyResolver::get_cloudflare_ips();
		$this->assertNotEmpty( $ips );
		$this->assertContains( '173.245.48.0/20', $ips );
		$this->assertContains( '2606:4700::/32', $ips );
		// Transients should now be populated.
		$this->assertNotEmpty( $GLOBALS['wp_test_transients'][ TrustedProxyResolver::TRANSIENT_CF_V4 ] );
		$this->assertNotEmpty( $GLOBALS['wp_test_transients'][ TrustedProxyResolver::TRANSIENT_CF_V6 ] );
	}

	// --- Settings storage ---

	public function test_settings_round_trip(): void {
		TrustedProxyResolver::update_settings( array(
			'enabled'   => true,
			'mode'      => TrustedProxyResolver::MODE_CUSTOM_LIST,
			'allowlist' => array( '10.0.0.0/8', 'bogus', '192.168.1.0/24' ),
		) );
		$settings = TrustedProxyResolver::get_settings();
		$this->assertTrue( $settings['enabled'] );
		$this->assertSame( TrustedProxyResolver::MODE_CUSTOM_LIST, $settings['mode'] );
		$this->assertContains( '10.0.0.0/8', $settings['allowlist'] );
		$this->assertContains( '192.168.1.0/24', $settings['allowlist'] );
		$this->assertNotContains( 'bogus', $settings['allowlist'] );
	}
}
