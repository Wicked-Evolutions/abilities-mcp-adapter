<?php
/**
 * Tests for OAuthScopeEnforcer::check_scope() — the explicit-scope entry
 * point added in #45 for dispatch paths without a WP_Ability (currently
 * the builder-based prompts path in PromptsHandler::get_prompt).
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthRequestContext;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthScopeEnforcer;
use WickedEvolutions\McpAdapter\Auth\OAuth\ScopeRegistry;

final class OAuthScopeEnforcerCheckScopeTest extends TestCase {

	protected function setUp(): void {
		OAuthRequestContext::reset();
	}

	private function set_oauth_request( array $scopes ): void {
		OAuthRequestContext::set(
			user_id: 7,
			scopes: $scopes,
			resource: 'https://example.com/wp-json/mcp/mcp-adapter-default-server',
			client_id: 'cl_test',
			token_id: 1
		);
	}

	public function test_non_oauth_request_is_noop(): void {
		$this->assertFalse( OAuthRequestContext::is_oauth_request() );
		$this->assertNull( OAuthScopeEnforcer::check_scope( 'abilities:mcp-adapter:read' ) );
	}

	public function test_direct_match_allows(): void {
		$this->set_oauth_request( array( 'abilities:mcp-adapter:read' ) );
		$this->assertNull( OAuthScopeEnforcer::check_scope( 'abilities:mcp-adapter:read' ) );
	}

	public function test_missing_scope_denies_with_required_in_payload(): void {
		$this->set_oauth_request( array( 'abilities:content:read' ) );

		$denial = OAuthScopeEnforcer::check_scope( 'abilities:mcp-adapter:read' );

		$this->assertIsArray( $denial );
		$this->assertSame( 'insufficient_scope', $denial['error_code'] );
		$this->assertSame( 'abilities:mcp-adapter:read', $denial['required_scope'] );
		$this->assertStringContainsString( 'abilities:mcp-adapter:read', $denial['message'] );
	}

	public function test_umbrella_grant_covers_non_sensitive_scope(): void {
		$this->set_oauth_request( ScopeRegistry::expand( array( 'abilities:read' ) ) );
		// `abilities:mcp-adapter:read` is non-sensitive and in the umbrella's implications.
		$this->assertNull( OAuthScopeEnforcer::check_scope( 'abilities:mcp-adapter:read' ) );
	}

	public function test_check_delegates_to_check_scope_for_ability_derived_scope(): void {
		// Regression: the existing check(WP_Ability) entry point must now route
		// through check_scope and behave identically.
		$this->set_oauth_request( array( 'abilities:content:write' ) );

		$ability = new \WP_Ability(
			'content/create',
			array(
				'category' => 'content',
				'meta'     => array( 'annotations' => array( 'permission' => 'write' ) ),
			)
		);

		$this->assertNull( OAuthScopeEnforcer::check( $ability ) );
	}
}
