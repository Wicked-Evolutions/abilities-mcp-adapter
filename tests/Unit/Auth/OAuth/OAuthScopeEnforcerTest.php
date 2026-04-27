<?php
/**
 * Tests for OAuthScopeEnforcer (issue #38 / H.1.3).
 *
 * Covers the four acceptance cases from issue #38 plus the required_scope_for()
 * mapping table.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthRequestContext;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthScopeEnforcer;
use WickedEvolutions\McpAdapter\Auth\OAuth\ScopeRegistry;
use WP_Ability;

final class OAuthScopeEnforcerTest extends TestCase {

	protected function setUp(): void {
		OAuthRequestContext::reset();
	}

	private function ability( string $name, string $category = '', array $annotations = array() ): WP_Ability {
		return new WP_Ability(
			$name,
			array(
				'category' => $category,
				'meta'     => array( 'annotations' => $annotations ),
			)
		);
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

	// ---------------------------------------------------------------------
	// Acceptance case 1 — abilities:read + module reads.
	// ---------------------------------------------------------------------

	public function test_abilities_read_allows_content_list(): void {
		// Issued tokens contain the umbrella plus its expanded children, so the
		// realistic granted set for `--scope abilities:read` includes both.
		$this->set_oauth_request( ScopeRegistry::expand( array( 'abilities:read' ) ) );

		$content_list = $this->ability( 'content/list', 'content', array( 'readonly' => true ) );

		$this->assertNull( OAuthScopeEnforcer::check( $content_list ) );
	}

	public function test_abilities_read_denies_content_create(): void {
		$this->set_oauth_request( ScopeRegistry::expand( array( 'abilities:read' ) ) );

		$content_create = $this->ability( 'content/create', 'content', array( 'permission' => 'write' ) );

		$denial = OAuthScopeEnforcer::check( $content_create );

		$this->assertIsArray( $denial );
		$this->assertSame( 'insufficient_scope', $denial['error_code'] );
		$this->assertSame( 'abilities:content:write', $denial['required_scope'] );
		$this->assertStringContainsString( 'abilities:content:write', $denial['message'] );
	}

	// ---------------------------------------------------------------------
	// Acceptance case 2 — abilities:write umbrella (non-sensitive vs sensitive).
	// ---------------------------------------------------------------------

	public function test_abilities_write_umbrella_allows_non_sensitive_write(): void {
		// Pre-expanded write umbrella — content:write IS in the implications list.
		$this->set_oauth_request( ScopeRegistry::expand( array( 'abilities:write' ) ) );

		$content_create = $this->ability( 'content/create', 'content', array( 'permission' => 'write' ) );

		$this->assertNull( OAuthScopeEnforcer::check( $content_create ) );
	}

	public function test_abilities_write_umbrella_denies_sensitive_users_create(): void {
		// Pre-expanded write umbrella — users:write is NOT in the implications list,
		// so the granted set won't contain it. Sensitive scopes are never implied.
		$this->set_oauth_request( ScopeRegistry::expand( array( 'abilities:write' ) ) );

		$users_create = $this->ability( 'users/create', 'users', array( 'permission' => 'write' ) );

		$denial = OAuthScopeEnforcer::check( $users_create );

		$this->assertIsArray( $denial );
		$this->assertSame( 'abilities:users:write', $denial['required_scope'] );
	}

	public function test_umbrella_only_token_still_denies_sensitive_scope(): void {
		// Defense-in-depth: even if a token somehow has only the umbrella string
		// (e.g. issued by a future code path that skipped expansion), sensitive
		// scopes must NOT be implied.
		$this->set_oauth_request( array( 'abilities:write' ) );

		$users_create = $this->ability( 'users/create', 'users', array( 'permission' => 'write' ) );

		$denial = OAuthScopeEnforcer::check( $users_create );

		$this->assertIsArray( $denial );
		$this->assertSame( 'abilities:users:write', $denial['required_scope'] );
	}

	public function test_umbrella_only_token_allows_non_sensitive_via_umbrella_fallback(): void {
		// Same defense-in-depth: umbrella-only token still allows non-sensitive
		// children when the umbrella covers them.
		$this->set_oauth_request( array( 'abilities:write' ) );

		$content_create = $this->ability( 'content/create', 'content', array( 'permission' => 'write' ) );

		$this->assertNull( OAuthScopeEnforcer::check( $content_create ) );
	}

	// ---------------------------------------------------------------------
	// Acceptance case 3 — explicit sensitive scope.
	// ---------------------------------------------------------------------

	public function test_explicit_sensitive_scope_allows_users_create(): void {
		$this->set_oauth_request( array( 'abilities:users:write' ) );

		$users_create = $this->ability( 'users/create', 'users', array( 'permission' => 'write' ) );

		$this->assertNull( OAuthScopeEnforcer::check( $users_create ) );
	}

	// ---------------------------------------------------------------------
	// Acceptance case 4 — non-OAuth request is a no-op.
	// ---------------------------------------------------------------------

	public function test_non_oauth_request_is_noop(): void {
		// No OAuthRequestContext::set() call — gate must allow.
		$users_create = $this->ability( 'users/create', 'users', array( 'permission' => 'write' ) );

		$this->assertFalse( OAuthRequestContext::is_oauth_request() );
		$this->assertNull( OAuthScopeEnforcer::check( $users_create ) );
	}

	// ---------------------------------------------------------------------
	// required_scope_for() mapping table.
	// ---------------------------------------------------------------------

	/**
	 * @dataProvider mapping_cases
	 */
	public function test_required_scope_for_maps_category_and_permission(
		string $category,
		array $annotations,
		string $expected
	): void {
		$ability = $this->ability( 'whatever', $category, $annotations );
		$this->assertSame( $expected, OAuthScopeEnforcer::required_scope_for( $ability ) );
	}

	public static function mapping_cases(): array {
		return array(
			'content read (explicit)'   => array( 'content', array( 'permission' => 'read' ),    'abilities:content:read' ),
			'content write (explicit)'  => array( 'content', array( 'permission' => 'write' ),   'abilities:content:write' ),
			'content delete (explicit)' => array( 'content', array( 'permission' => 'delete' ),  'abilities:content:delete' ),
			'users write (explicit)'    => array( 'users',   array( 'permission' => 'write' ),   'abilities:users:write' ),
			'plugins delete (explicit)' => array( 'plugins', array( 'permission' => 'delete' ),  'abilities:plugins:delete' ),
			'readonly annotation'       => array( 'media',   array( 'readonly' => true ),        'abilities:media:read' ),
			'destructive annotation'    => array( 'menus',   array( 'destructive' => true ),     'abilities:menus:delete' ),
			'no annotations defaults read' => array( 'taxonomies', array(),                      'abilities:taxonomies:read' ),
			'empty category falls back to mcp-adapter' => array( '', array( 'permission' => 'read' ), 'abilities:mcp-adapter:read' ),
		);
	}
}