<?php
/**
 * #88: authenticate_bearer must surface the persisted selected_role into
 * OAuthRequestContext so SelectedRoleEnforcer can downgrade caps.
 *
 * Confirms the integration point between TokenStore (writes the role) and
 * SelectedRoleEnforcer (reads from OAuthRequestContext). If this test passes
 * but a downgrade isn't observed live, look at the user_has_cap filter
 * registration; the role-plumbing chain is verified here.
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

final class AuthenticateBearerSelectedRoleTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		$this->original_wpdb = $GLOBALS['wpdb'];
		OAuthRequestContext::reset();
		// Pin REQUEST_URI to a path oauth_is_mcp_resource_request() accepts.
		$_SERVER['REQUEST_URI']        = '/wp-json/mcp/abilities-mcp-adapter-default-server';
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer some-plaintext-token';
		$GLOBALS['wp_test_home_url']   = 'https://example.com';
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->original_wpdb;
		unset( $_SERVER['REQUEST_URI'], $_SERVER['HTTP_AUTHORIZATION'] );
		unset( $GLOBALS['wp_test_home_url'] );
		OAuthRequestContext::reset();
	}

	/** Build a valid not-expired, not-revoked token row with a configurable selected_role. */
	private function install_token_row( string $selected_role ): void {
		$row                = new \stdClass();
		$row->id            = 7;
		$row->user_id       = 42;
		$row->client_id     = 'client_abc';
		$row->scope         = 'abilities:content:read';
		$row->resource      = 'https://example.com/wp-json/mcp/abilities-mcp-adapter-default-server';
		$row->token_hash    = 'h';
		$row->selected_role = $selected_role;
		$row->expires_at    = ( new \DateTimeImmutable( '+1 hour', new \DateTimeZone( 'UTC' ) ) )
			->format( 'Y-m-d H:i:s' );
		$row->revoked       = 0;

		$GLOBALS['wpdb'] = new class( $row ) {
			public string $prefix = 'wp_';
			public function __construct( public \stdClass $row ) {}
			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )         { return $this->row; }
			public function get_results( $q )     { return array( $this->row ); }
			public function get_var( $q )         { return null; }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null )                  { return 1; }
			public function query( $sql )                                 { return true; }
		};
	}

	public function test_populates_selected_role_into_request_context(): void {
		$this->install_token_row( 'editor' );

		AuthorizationServer::authenticate_bearer( false );

		$this->assertTrue( OAuthRequestContext::is_oauth_request() );
		$this->assertSame( 42, OAuthRequestContext::user_id() );
		$this->assertSame( 'editor', OAuthRequestContext::selected_role() );
	}

	public function test_empty_selected_role_yields_empty_context_role(): void {
		// Tokens issued via the auto-approve path or pre-fix tokens have
		// selected_role=''. Pinned so the carve-out is visible at this layer
		// (CHANGELOG known limitation, follow-up #94).
		$this->install_token_row( '' );

		AuthorizationServer::authenticate_bearer( false );

		$this->assertTrue( OAuthRequestContext::is_oauth_request() );
		$this->assertSame( '', OAuthRequestContext::selected_role() );
	}

	public function test_missing_selected_role_property_defaults_to_empty(): void {
		// Defensive: a token row read from a pre-migration table won't have
		// the selected_role property. The bearer-auth path must default to
		// '' rather than throwing.
		$row              = new \stdClass();
		$row->id          = 7;
		$row->user_id     = 42;
		$row->client_id   = 'client_abc';
		$row->scope       = 'abilities:content:read';
		$row->resource    = 'https://example.com/wp-json/mcp/abilities-mcp-adapter-default-server';
		$row->token_hash  = 'h';
		$row->expires_at  = ( new \DateTimeImmutable( '+1 hour', new \DateTimeZone( 'UTC' ) ) )
			->format( 'Y-m-d H:i:s' );
		$row->revoked     = 0;
		// no selected_role property

		$GLOBALS['wpdb'] = new class( $row ) {
			public string $prefix = 'wp_';
			public function __construct( public \stdClass $row ) {}
			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )         { return $this->row; }
			public function get_results( $q )     { return array( $this->row ); }
			public function get_var( $q )         { return null; }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null )                  { return 1; }
			public function query( $sql )                                 { return true; }
		};

		AuthorizationServer::authenticate_bearer( false );

		$this->assertTrue( OAuthRequestContext::is_oauth_request() );
		$this->assertSame( '', OAuthRequestContext::selected_role() );
	}
}
