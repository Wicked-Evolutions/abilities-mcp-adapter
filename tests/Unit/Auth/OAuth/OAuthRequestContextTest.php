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

	public function test_oauth_has_scope_returns_false_when_not_oauth(): void {
		// M-3 (2026-04-27 audit): strict contract — non-OAuth requests return
		// false so callers MUST handle the non-OAuth path explicitly. The
		// previous "true → caps govern" default was trivially fail-open if a
		// future caller used this as the sole authorization gate.
		$this->assertFalse( OAuthRequestContext::oauth_has_scope( 'abilities:write' ) );
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

	public function test_oauth_has_scope_exact_match(): void {
		OAuthRequestContext::set( user_id: 1, scopes: [ 'abilities:read' ], resource: '', client_id: '', token_id: 0 );

		$this->assertTrue( OAuthRequestContext::oauth_has_scope( 'abilities:read' ) );
		$this->assertFalse( OAuthRequestContext::oauth_has_scope( 'abilities:write' ) );
	}

	public function test_oauth_has_scope_does_not_expand_umbrella_grants(): void {
		// Direct in_array match only. Umbrella expansion is a separate
		// concern handled by OAuthScopeEnforcer::check_scope() for non-
		// sensitive scopes. Sensitive scopes are NEVER implied by umbrella.
		OAuthRequestContext::set(
			user_id: 1,
			scopes: [ 'abilities:content' ], // umbrella, not the leaf
			resource: '',
			client_id: '',
			token_id: 0
		);

		$this->assertTrue(  OAuthRequestContext::oauth_has_scope( 'abilities:content' ) );
		$this->assertFalse( OAuthRequestContext::oauth_has_scope( 'abilities:content:read' ) );
	}

	public function test_reset_clears_context(): void {
		OAuthRequestContext::set( user_id: 1, scopes: [ 'abilities:read' ], resource: '', client_id: '', token_id: 0 );
		OAuthRequestContext::reset();

		$this->assertFalse( OAuthRequestContext::is_oauth_request() );
		$this->assertSame( [], OAuthRequestContext::granted_scopes() );
	}
}
