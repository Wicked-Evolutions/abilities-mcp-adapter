<?php
/**
 * #91: oauth_client_ip() must not honor X-Forwarded-For from untrusted sources.
 *
 * Pre-fix the helper had two failure modes that combined into a DCR/revoke
 * rate-limit bypass:
 *   1. WP_OAUTH_TRUST_FORWARDED_HOST=true was the only gate.
 *   2. With the constant on, the helper read $_SERVER['HTTP_X_FORWARDED_FOR']
 *      directly, no REMOTE_ADDR allowlist check. A caller could rotate spoofed
 *      values to bucket each request into a unique rate-limit slot.
 *
 * After fix the helper delegates to TrustedProxyResolver::resolve(), which
 * gates forwarded headers on REMOTE_ADDR being in the trusted-proxy allowlist
 * (Cloudflare CIDRs or operator-configured custom list via Safety Settings).
 *
 * Each test runs in its own PHP process so WP_OAUTH_TRUST_FORWARDED_HOST can
 * be set to a different value per case (PHP constants cannot be redefined
 * within a single process, so per-test isolation is the cheapest correct
 * approach for this matrix).
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Settings\SafetySettingsRepository;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
final class OAuthClientIpTrustedProxyTest extends TestCase {

	protected function setUp(): void {
		unset(
			$_SERVER['REMOTE_ADDR'],
			$_SERVER['HTTP_X_FORWARDED_FOR'],
			$_SERVER['HTTP_X_REAL_IP'],
			$_SERVER['HTTP_CF_CONNECTING_IP'],
			$_SERVER['HTTP_TRUE_CLIENT_IP']
		);
		$GLOBALS['wp_test_options']    = array();
		$GLOBALS['wp_test_transients'] = array();
	}

	private function configure_resolver_disabled(): void {
		// Default — no Safety Settings touched, resolver returns REMOTE_ADDR.
		// Explicitly persist 'off' to be unambiguous.
		SafetySettingsRepository::set_trusted_proxy_enabled( false );
	}

	private function configure_resolver_with_allowlist( array $cidrs ): void {
		SafetySettingsRepository::set_trusted_proxy_enabled( true );
		SafetySettingsRepository::set_trusted_proxy_mode( SafetySettingsRepository::PROXY_MODE_CUSTOM );
		SafetySettingsRepository::set_trusted_proxy_allowlist_raw( implode( "\n", $cidrs ) );
	}

	// ─── Case 1: constant undefined → REMOTE_ADDR (legacy safe path) ────────
	public function test_constant_undefined_returns_remote_addr_ignoring_xff(): void {
		$_SERVER['REMOTE_ADDR']          = '198.51.100.7';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.99';
		$this->assertSame( '198.51.100.7', \oauth_client_ip() );
	}

	// ─── Case 2: constant on, resolver disabled → REMOTE_ADDR ───────────────
	public function test_constant_on_resolver_disabled_returns_remote_addr(): void {
		define( 'WP_OAUTH_TRUST_FORWARDED_HOST', true );
		$_SERVER['REMOTE_ADDR']          = '198.51.100.7';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.99';
		$this->configure_resolver_disabled();
		$this->assertSame( '198.51.100.7', \oauth_client_ip() );
	}

	// ─── Case 3: BYPASS CLOSURE — constant on, resolver enabled, REMOTE_ADDR
	// not in the allowlist, XFF spoofed → must return REMOTE_ADDR. ──────────
	public function test_bypass_closure_remote_addr_not_in_allowlist_returns_remote_addr(): void {
		define( 'WP_OAUTH_TRUST_FORWARDED_HOST', true );
		// Untrusted source IP — NOT in the allowlist.
		$_SERVER['REMOTE_ADDR']          = '198.51.100.7';
		// Caller rotates spoofed forwarded values trying to bucket-evade.
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.99';
		$this->configure_resolver_with_allowlist( array( '10.0.0.0/8' ) );
		$this->assertSame(
			'198.51.100.7',
			\oauth_client_ip(),
			'Untrusted REMOTE_ADDR must not have its X-Forwarded-For honored — rate-limit bypass closure (#91).'
		);
	}

	// ─── Case 4: constant on, resolver enabled, REMOTE_ADDR is a real proxy,
	// XFF set → returns XFF first IP. Real proxy deployments still work. ────
	public function test_real_proxy_remote_addr_in_allowlist_returns_forwarded_ip(): void {
		define( 'WP_OAUTH_TRUST_FORWARDED_HOST', true );
		$_SERVER['REMOTE_ADDR']          = '10.0.0.5';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.99';
		$this->configure_resolver_with_allowlist( array( '10.0.0.0/8' ) );
		$this->assertSame( '203.0.113.99', \oauth_client_ip() );
	}

	// ─── Case 5: constant on, resolver enabled, REMOTE_ADDR in allowlist,
	// no XFF → returns REMOTE_ADDR (no header to honor). ─────────────────────
	public function test_real_proxy_no_xff_returns_remote_addr(): void {
		define( 'WP_OAUTH_TRUST_FORWARDED_HOST', true );
		$_SERVER['REMOTE_ADDR'] = '10.0.0.5';
		$this->configure_resolver_with_allowlist( array( '10.0.0.0/8' ) );
		$this->assertSame( '10.0.0.5', \oauth_client_ip() );
	}

	// ─── Case 6: constant undefined, no XFF → REMOTE_ADDR. ──────────────────
	public function test_constant_undefined_no_xff_returns_remote_addr(): void {
		$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
		$this->assertSame( '198.51.100.7', \oauth_client_ip() );
	}

	// ─── Case 7: empty REMOTE_ADDR falls back to '0.0.0.0' (boundary log
	// compatibility — pre-fix value preserved). Constant on path. ───────────
	public function test_empty_remote_addr_falls_back_to_zero_with_constant_on(): void {
		define( 'WP_OAUTH_TRUST_FORWARDED_HOST', true );
		// REMOTE_ADDR not set; resolver returns '' for missing/invalid REMOTE_ADDR.
		$this->configure_resolver_disabled();
		$this->assertSame( '0.0.0.0', \oauth_client_ip() );
	}

	// ─── Case 8: empty REMOTE_ADDR with constant off also falls back to '0.0.0.0'. ──
	public function test_empty_remote_addr_falls_back_to_zero_with_constant_off(): void {
		// REMOTE_ADDR not set; constant not defined.
		$this->assertSame( '0.0.0.0', \oauth_client_ip() );
	}

	// ─── Case 9: BYPASS CLOSURE / multi-value XFF — caller rotating multiple
	// spoofed values must still bucket on REMOTE_ADDR. ───────────────────────
	public function test_multi_value_xff_from_untrusted_source_collapses_to_remote_addr(): void {
		define( 'WP_OAUTH_TRUST_FORWARDED_HOST', true );
		$_SERVER['REMOTE_ADDR']          = '198.51.100.7';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.1, 203.0.113.2, 203.0.113.3';
		$this->configure_resolver_with_allowlist( array( '10.0.0.0/8' ) );
		$this->assertSame( '198.51.100.7', \oauth_client_ip() );
	}
}
