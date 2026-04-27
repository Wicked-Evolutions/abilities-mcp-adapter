<?php
/**
 * Regression test for C-1: AuthorizationServer::authenticate_bearer() must
 * be a no-op on every URI that is not the MCP resource endpoint, even when
 * a valid token is in the database.
 *
 * Before the fix: a token issued for the MCP resource passed the
 * resource_match check (which only compared the token's resource against
 * a constant) and authenticated the user on /wp-json/wp/v2/* and every
 * other REST route, where the OAuth scope enforcer never fires.
 *
 * After the fix: bearer auth is gated on
 * oauth_is_mcp_resource_request() — non-MCP REST routes return the input
 * $user_id unchanged.
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

final class AuthenticateBearerNarrowsToMcpResourceTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		parent::setUp();
		$this->original_wpdb = $GLOBALS['wpdb'];
		OAuthRequestContext::reset();
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb']                  = $this->original_wpdb;
		unset( $_SERVER['REQUEST_URI'] );
		unset( $_SERVER['HTTP_AUTHORIZATION'] );
		OAuthRequestContext::reset();
		parent::tearDown();
	}

	/** Build a $wpdb stub whose get_row() returns a not-expired, not-revoked token row. */
	private function install_valid_token_row(): void {
		$expires_at = ( new \DateTimeImmutable( '+1 hour', new \DateTimeZone( 'UTC' ) ) )
			->format( 'Y-m-d H:i:s' );

		$row              = new \stdClass();
		$row->id          = 7;
		$row->user_id     = 42;
		$row->client_id   = 'client_abc';
		$row->scope       = 'abilities:content:read';
		$row->resource    = 'https://example.com/wp-json/mcp/mcp-adapter-default-server';
		$row->token_hash  = 'h';
		$row->expires_at  = $expires_at;
		$row->revoked     = 0;

		$GLOBALS['wpdb'] = new class( $row ) {
			public string $prefix = 'wp_';
			private \stdClass $row;
			public function __construct( \stdClass $row ) { $this->row = $row; }
			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )     { return $this->row; }
			public function get_results( $q ) { return [ $this->row ]; }
			public function get_var( $q )     { return null; }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null )                  { return 1; }
			public function query( $sql )                                 { return true; }
		};
	}

	public function test_no_op_on_wp_v2_users_even_with_valid_token(): void {
		$this->install_valid_token_row();
		$_SERVER['REQUEST_URI']        = '/wp-json/wp/v2/users';
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer some-plaintext-token';

		$result = AuthorizationServer::authenticate_bearer( false );

		$this->assertFalse( $result, '/wp-json/wp/v2/users must not authenticate via the MCP token' );
		$this->assertFalse(
			OAuthRequestContext::is_oauth_request(),
			'OAuthRequestContext must not be populated on non-MCP routes'
		);
	}

	public function test_no_op_on_wp_v2_plugins_even_with_valid_token(): void {
		$this->install_valid_token_row();
		$_SERVER['REQUEST_URI']        = '/wp-json/wp/v2/plugins';
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer some-plaintext-token';

		$this->assertFalse( AuthorizationServer::authenticate_bearer( false ) );
		$this->assertFalse( OAuthRequestContext::is_oauth_request() );
	}

	public function test_no_op_on_oauth_token_endpoint_even_with_valid_token(): void {
		// /wp-json/mcp/oauth/token is in the MCP namespace but is not the
		// MCP resource — bearer auth must not fire (RFC 7009 client auth on
		// the revoke endpoint is the concern of #46, not bearer auth here).
		$this->install_valid_token_row();
		$_SERVER['REQUEST_URI']        = '/wp-json/mcp/oauth/token';
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer some-plaintext-token';

		$this->assertFalse( AuthorizationServer::authenticate_bearer( false ) );
		$this->assertFalse( OAuthRequestContext::is_oauth_request() );
	}

	public function test_authenticates_on_mcp_resource_with_valid_token(): void {
		$this->install_valid_token_row();
		$_SERVER['REQUEST_URI']        = '/wp-json/mcp/mcp-adapter-default-server';
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer some-plaintext-token';

		$result = AuthorizationServer::authenticate_bearer( false );

		$this->assertSame( 42, $result, 'Valid token must authenticate on the MCP resource' );
		$this->assertTrue(
			OAuthRequestContext::is_oauth_request(),
			'OAuthRequestContext must be populated on the MCP resource'
		);
		$this->assertSame( 42, OAuthRequestContext::user_id() );
		$this->assertSame( [ 'abilities:content:read' ], OAuthRequestContext::granted_scopes() );
	}

	public function test_already_authenticated_user_passes_through_unchanged(): void {
		$_SERVER['REQUEST_URI']        = '/wp-json/wp/v2/posts';
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer some-plaintext-token';

		// Higher-priority filter has already resolved a user (e.g., cookie auth).
		$this->assertSame( 11, AuthorizationServer::authenticate_bearer( 11 ) );
	}
}
