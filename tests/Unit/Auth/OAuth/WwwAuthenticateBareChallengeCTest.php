<?php
/**
 * C-3: WWW-Authenticate bare challenge when no Authorization header is presented.
 *
 * Pre-fix: AuthorizationServer::authenticate_bearer() returned early with no
 * header when the request had no Authorization header — even on the protected
 * MCP resource endpoint. Standards-compliant clients could not discover the
 * protected-resource metadata URL.
 *
 * After fix: when the request targets the MCP resource endpoint and no
 * Authorization header is present, a bare RFC 6750 §3 challenge is scheduled
 * (realm + resource_metadata, no error/error_description).
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationServer;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthRequestContext;

if ( ! defined( 'REST_REQUEST' ) ) {
	define( 'REST_REQUEST', true );
}

final class WwwAuthenticateBareChallengeCTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['wp_test_filters'] = array();
		OAuthRequestContext::reset();
		unset( $_SERVER['REQUEST_URI'], $_SERVER['HTTP_AUTHORIZATION'] );
	}

	protected function tearDown(): void {
		$GLOBALS['wp_test_filters'] = array();
		unset( $_SERVER['REQUEST_URI'], $_SERVER['HTTP_AUTHORIZATION'] );
		OAuthRequestContext::reset();
		parent::tearDown();
	}

	/**
	 * On the MCP resource endpoint with no Authorization header, the
	 * rest_post_dispatch filter must be registered (bare challenge scheduled).
	 */
	public function test_bare_challenge_scheduled_for_mcp_resource_with_no_token(): void {
		$_SERVER['REQUEST_URI'] = '/wp-json/mcp/mcp-adapter-default-server';
		unset( $_SERVER['HTTP_AUTHORIZATION'] );

		$result = AuthorizationServer::authenticate_bearer( false );

		$this->assertFalse( $result );
		// The bare-challenge filter must have been registered.
		$this->assertNotEmpty(
			$GLOBALS['wp_test_filters']['rest_post_dispatch'] ?? array(),
			'rest_post_dispatch filter must be registered for the bare C-3 challenge'
		);
	}

	/**
	 * On a non-MCP route with no Authorization header, no WWW-Authenticate is
	 * scheduled (the endpoint is not a protected resource for our tokens).
	 */
	public function test_no_challenge_scheduled_for_non_mcp_route_with_no_token(): void {
		$_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';
		unset( $_SERVER['HTTP_AUTHORIZATION'] );

		$before = count( $GLOBALS['wp_test_filters']['rest_post_dispatch'] ?? array() );
		AuthorizationServer::authenticate_bearer( false );
		$after = count( $GLOBALS['wp_test_filters']['rest_post_dispatch'] ?? array() );

		$this->assertSame( $before, $after, 'No WWW-Authenticate should be scheduled for non-MCP routes' );
	}

	/**
	 * Lock-in: the closure registered for the bare challenge must NOT include
	 * error or error_description parameters (only realm + resource_metadata).
	 */
	public function test_bare_challenge_closure_has_empty_error_code(): void {
		$_SERVER['REQUEST_URI'] = '/wp-json/mcp/mcp-adapter-default-server';
		unset( $_SERVER['HTTP_AUTHORIZATION'] );

		AuthorizationServer::authenticate_bearer( false );

		$entries = $GLOBALS['wp_test_filters']['rest_post_dispatch'] ?? array();
		$this->assertNotEmpty( $entries );

		// Extract the closure from the last registered entry.
		$last    = end( $entries );
		$closure = $last['cb'];
		$this->assertIsCallable( $closure );

		// Inspect captured variables via reflection to confirm error_code = ''.
		$rf       = new \ReflectionFunction( $closure );
		$vars     = $rf->getStaticVariables();
		$this->assertSame( '', $vars['error_code'], 'Bare challenge must have empty error_code' );
		$this->assertSame( '', $vars['description'], 'Bare challenge must have empty description' );
	}

	/**
	 * When a malformed Bearer token is presented (non-empty Authorization header
	 * but format is wrong), a challenge is still scheduled. This is distinct
	 * from the bare case — the client sent something that looks like auth.
	 */
	public function test_challenge_with_invalid_token_format_is_scheduled(): void {
		$_SERVER['REQUEST_URI']        = '/wp-json/mcp/mcp-adapter-default-server';
		$_SERVER['HTTP_AUTHORIZATION'] = 'Basic dXNlcjpwYXNz';

		// Basic auth, not Bearer — should fall through and schedule bare challenge.
		AuthorizationServer::authenticate_bearer( false );

		$this->assertNotEmpty(
			$GLOBALS['wp_test_filters']['rest_post_dispatch'] ?? array(),
			'WWW-Authenticate must still be scheduled for non-Bearer Authorization'
		);
	}
}
