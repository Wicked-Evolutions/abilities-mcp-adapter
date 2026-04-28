<?php
/**
 * M-2: OAuthRequestContext::reset() must fire on every WP-bootstrapped request.
 *
 * Pre-fix: reset was wired only to rest_api_init. PHP-FPM workers handling
 * a sequence of REST + non-REST requests retained stale singleton state. A
 * future caller adding has_scope() / is_oauth_request() on a non-REST surface
 * (cron, admin-ajax, CLI) would read context from a prior REST request on
 * the same worker.
 *
 * After fix: reset is also wired to init priority 0 — fires for every
 * WP-bootstrapped request. The rest_api_init wiring is kept as belt-and-suspenders.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationServer;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthRequestContext;

final class OAuthRequestContextResetTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_actions'] = array();
		// Flip the boot guard so we can re-run boot() in the test. The static
		// property is private; we read by name not value to keep the test from
		// caring about other properties on the class.
		$ref = new \ReflectionClass( AuthorizationServer::class );
		$prop = $ref->getProperty( 'booted' );
		$prop->setValue( null, false );

		AuthorizationServer::boot();
	}

	protected function tearDown(): void {
		$GLOBALS['wp_test_actions'] = array();
	}

	public function test_reset_is_wired_to_init_priority_zero(): void {
		$found = false;
		foreach ( $GLOBALS['wp_test_actions'] as $entry ) {
			if (
				$entry['hook'] === 'init'
				&& $entry['priority'] === 0
				&& is_array( $entry['callback'] )
				&& $entry['callback'][0] === OAuthRequestContext::class
				&& $entry['callback'][1] === 'reset'
			) {
				$found = true;
				break;
			}
		}
		$this->assertTrue( $found, 'OAuthRequestContext::reset() must be wired to init priority 0 (M-2)' );
	}

	public function test_reset_is_still_wired_to_rest_api_init(): void {
		// Belt-and-suspenders: the rest_api_init wiring is retained.
		$found = false;
		foreach ( $GLOBALS['wp_test_actions'] as $entry ) {
			if (
				$entry['hook'] === 'rest_api_init'
				&& is_array( $entry['callback'] )
				&& $entry['callback'][0] === OAuthRequestContext::class
				&& $entry['callback'][1] === 'reset'
			) {
				$found = true;
				break;
			}
		}
		$this->assertTrue( $found, 'rest_api_init reset wiring must be preserved' );
	}

	public function test_reset_clears_set_context(): void {
		// Functional verification that reset() actually clears state — the
		// behaviour the wiring is meant to invoke between requests.
		OAuthRequestContext::set(
			user_id: 7,
			scopes: array( 'abilities:content:read' ),
			resource: 'https://example.com/wp-json/mcp/mcp-adapter-default-server',
			client_id: 'cl_test',
			token_id: 1
		);
		$this->assertTrue( OAuthRequestContext::is_oauth_request() );

		OAuthRequestContext::reset();
		$this->assertFalse( OAuthRequestContext::is_oauth_request(), 'After reset, no OAuth context should remain' );
	}
}
