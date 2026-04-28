<?php
/**
 * M-6: REST routes for /wp-json/mcp/oauth/{register,token,revoke} must run
 * the OAuthHostAllowlist gate as their permission_callback.
 *
 * Pre-fix: only the pre-WP path (/oauth/authorize, /.well-known/*) checked
 * the allowlist. The REST endpoints used '__return_true' as their callback,
 * so a request from an unknown host could register clients, exchange codes,
 * and revoke tokens — defeating the allowlist.
 *
 * After fix: AuthorizationServer::rest_host_allowlist_gate() runs before
 * each REST callback; unknown hosts get a 404 WP_Error and a
 * boundary.oauth_host_rejected event is logged.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationServer;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthHostAllowlist;

final class RestRouteHostAllowlistTest extends TestCase {

	protected function setUp(): void {
		OAuthHostAllowlist::reset();
		$GLOBALS['wp_test_actions_invoked'] = array();
		// Keep global host clean; each test sets its own.
		unset( $_SERVER['HTTP_HOST'] );
	}

	protected function tearDown(): void {
		OAuthHostAllowlist::reset();
		$GLOBALS['wp_test_actions_invoked'] = array();
		unset( $_SERVER['HTTP_HOST'] );
	}

	public function test_gate_allows_request_from_allowed_host(): void {
		OAuthHostAllowlist::override( array( 'allowed.example.com' ) );
		$_SERVER['HTTP_HOST'] = 'allowed.example.com';

		$result = AuthorizationServer::rest_host_allowlist_gate();
		$this->assertTrue( $result, 'Allowed hosts must pass the gate (return true)' );
	}

	public function test_gate_rejects_request_from_unknown_host(): void {
		OAuthHostAllowlist::override( array( 'allowed.example.com' ) );
		$_SERVER['HTTP_HOST'] = 'attacker.example.com';

		$result = AuthorizationServer::rest_host_allowlist_gate();
		$this->assertInstanceOf( \WP_Error::class, $result, 'Unknown host must return WP_Error' );
		$this->assertSame( 'rest_no_route', $result->get_error_code() );
	}

	public function test_gate_returns_404_status_on_rejection(): void {
		OAuthHostAllowlist::override( array( 'allowed.example.com' ) );
		$_SERVER['HTTP_HOST'] = 'attacker.example.com';

		$result = AuthorizationServer::rest_host_allowlist_gate();
		$this->assertInstanceOf( \WP_Error::class, $result );
		$data = $result->get_error_data();
		$this->assertIsArray( $data );
		$this->assertSame( 404, $data['status'] ?? 0, 'Rejection status must be 404 (parity with pre-WP path)' );
	}

	public function test_gate_emits_boundary_event_on_rejection(): void {
		OAuthHostAllowlist::override( array( 'allowed.example.com' ) );
		$_SERVER['HTTP_HOST'] = 'attacker.example.com';

		AuthorizationServer::rest_host_allowlist_gate();

		$saw_event = false;
		foreach ( $GLOBALS['wp_test_actions_invoked'] as $entry ) {
			if (
				$entry['hook'] === 'mcp_adapter_boundary_event'
				&& isset( $entry['args'][0] )
				&& $entry['args'][0] === 'boundary.oauth_host_rejected'
			) {
				$saw_event = true;
				break;
			}
		}
		$this->assertTrue( $saw_event, 'Rejection must emit boundary.oauth_host_rejected (parity with pre-WP path)' );
	}

	public function test_gate_does_not_emit_boundary_event_on_allow(): void {
		OAuthHostAllowlist::override( array( 'allowed.example.com' ) );
		$_SERVER['HTTP_HOST'] = 'allowed.example.com';

		AuthorizationServer::rest_host_allowlist_gate();

		$saw_event = false;
		foreach ( $GLOBALS['wp_test_actions_invoked'] as $entry ) {
			if (
				$entry['hook'] === 'mcp_adapter_boundary_event'
				&& isset( $entry['args'][0] )
				&& $entry['args'][0] === 'boundary.oauth_host_rejected'
			) {
				$saw_event = true;
				break;
			}
		}
		$this->assertFalse( $saw_event, 'Allowed requests must not log a host_rejected event' );
	}

	public function test_gate_with_missing_http_host_is_rejected(): void {
		OAuthHostAllowlist::override( array( 'allowed.example.com' ) );
		// HTTP_HOST not set — empty string is not in the allowlist.
		$result = AuthorizationServer::rest_host_allowlist_gate();
		$this->assertInstanceOf( \WP_Error::class, $result, 'Missing HTTP_HOST must be rejected' );
	}
}
