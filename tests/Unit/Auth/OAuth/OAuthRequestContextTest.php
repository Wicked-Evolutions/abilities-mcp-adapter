<?php
/**
 * Tests for OAuthRequestContext singleton.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthRequestContext;

final class OAuthRequestContextTest extends TestCase {

	protected function setUp(): void {
		OAuthRequestContext::reset();
	}

	public function test_is_not_oauth_request_before_set(): void {
		$this->assertFalse( OAuthRequestContext::is_oauth_request() );
	}

	public function test_has_scope_returns_true_when_not_oauth(): void {
		// Non-OAuth requests: WP caps govern, scope checks pass through.
		$this->assertTrue( OAuthRequestContext::has_scope( 'abilities:write' ) );
	}

	public function test_granted_scopes_empty_before_set(): void {
		$this->assertSame( [], OAuthRequestContext::granted_scopes() );
	}

	public function test_set_populates_context(): void {
		OAuthRequestContext::set(
			user_id: 7,
			scopes: [ 'abilities:read', 'abilities:write' ],
			resource: 'https://example.com/wp-json/mcp/mcp-adapter-default-server',
			client_id: 'cl_abc',
			token_id: 42
		);

		$this->assertTrue( OAuthRequestContext::is_oauth_request() );
		$this->assertSame( 7, OAuthRequestContext::user_id() );
		$this->assertSame( [ 'abilities:read', 'abilities:write' ], OAuthRequestContext::granted_scopes() );
		$this->assertSame( 'https://example.com/wp-json/mcp/mcp-adapter-default-server', OAuthRequestContext::resource() );
		$this->assertSame( 'cl_abc', OAuthRequestContext::client_id() );
		$this->assertSame( 42, OAuthRequestContext::token_id() );
	}

	public function test_has_scope_exact_match(): void {
		OAuthRequestContext::set( user_id: 1, scopes: [ 'abilities:read' ], resource: '', client_id: '', token_id: 0 );

		$this->assertTrue( OAuthRequestContext::has_scope( 'abilities:read' ) );
		$this->assertFalse( OAuthRequestContext::has_scope( 'abilities:write' ) );
	}

	public function test_reset_clears_context(): void {
		OAuthRequestContext::set( user_id: 1, scopes: [ 'abilities:read' ], resource: '', client_id: '', token_id: 0 );
		OAuthRequestContext::reset();

		$this->assertFalse( OAuthRequestContext::is_oauth_request() );
		$this->assertSame( [], OAuthRequestContext::granted_scopes() );
	}
}
