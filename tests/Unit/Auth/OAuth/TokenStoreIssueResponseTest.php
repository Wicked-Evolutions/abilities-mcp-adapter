<?php
/**
 * H-6: token_type and scope fields in TokenStore::issue() response.
 *
 * Pre-fix: TokenStore::issue() returned {access_token, refresh_token, expires_in,
 * scope} — `token_type` was absent. RFC 6749 §5.1 marks it REQUIRED. Standards-
 * compliant third-party clients listed in Appendix E reject responses without it.
 *
 * After fix: `token_type: Bearer` is always present in the response.
 *
 * Scope-return policy (documented here for RFC 6749 §3.3):
 *   The stored scope is the umbrella-expanded set (ScopeRegistry::expand() is
 *   called in AuthorizeRequestValidator before the code is minted). The token
 *   response returns this stored set verbatim. Because the expanded set always
 *   differs from the umbrella strings the client requested, §3.3's "MUST include
 *   when different from requested" rule requires returning it — which we do.
 *   Returning the authoritative expanded set also gives the client an exact
 *   picture of what the token can do, which is the safer choice.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\TokenStore;

final class TokenStoreIssueResponseTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		$this->original_wpdb = $GLOBALS['wpdb'];
		$this->install_stub_wpdb();
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->original_wpdb;
	}

	/**
	 * Install a $wpdb stub that satisfies TokenStore::issue():
	 *   - query() returns true (START TRANSACTION / COMMIT)
	 *   - insert() returns 1
	 *   - insert_id property = 99 (access token row id for the refresh FK)
	 * apply_filters() no-ops from bootstrap, so TTLs pass through unchanged.
	 */
	private function install_stub_wpdb(): void {
		$GLOBALS['wpdb'] = new class {
			public string $prefix    = 'wp_';
			public int    $insert_id = 99;

			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )         { return null; }
			public function get_var( $q )         { return null; }
			public function get_results( $q )     { return array(); }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null ) { return 1; }
			public function query( $sql )         { return true; }
		};
	}

	// -------------------------------------------------------------------------
	// token_type
	// -------------------------------------------------------------------------

	public function test_issue_includes_token_type_bearer(): void {
		$pair = TokenStore::issue( 'cl_test', 1, 'abilities:content:read', 'https://example.com/wp-json/mcp/mcp-adapter-default-server' );

		$this->assertArrayHasKey( 'token_type', $pair, 'token_type must be present (RFC 6749 §5.1 REQUIRED)' );
		$this->assertSame( 'Bearer', $pair['token_type'] );
	}

	public function test_token_type_is_case_correct_Bearer(): void {
		$pair = TokenStore::issue( 'cl_test', 1, 'abilities:content:read', 'https://example.com/wp-json/mcp/mcp-adapter-default-server' );

		// RFC 6749 §7.1 defines token type identifiers as case-insensitive, but
		// RFC 6750 §1 uses "Bearer" (capital B). Return the canonical form.
		$this->assertSame( 'Bearer', $pair['token_type'] );
	}

	// -------------------------------------------------------------------------
	// Existing fields still present (regression guard)
	// -------------------------------------------------------------------------

	public function test_issue_still_returns_access_token(): void {
		$pair = TokenStore::issue( 'cl_test', 1, 'abilities:content:read', 'https://example.com/wp-json/mcp/mcp-adapter-default-server' );
		$this->assertArrayHasKey( 'access_token', $pair );
		$this->assertNotEmpty( $pair['access_token'] );
	}

	public function test_issue_still_returns_refresh_token(): void {
		$pair = TokenStore::issue( 'cl_test', 1, 'abilities:content:read', 'https://example.com/wp-json/mcp/mcp-adapter-default-server' );
		$this->assertArrayHasKey( 'refresh_token', $pair );
		$this->assertNotEmpty( $pair['refresh_token'] );
	}

	public function test_issue_still_returns_expires_in(): void {
		$pair = TokenStore::issue( 'cl_test', 1, 'abilities:content:read', 'https://example.com/wp-json/mcp/mcp-adapter-default-server' );
		$this->assertArrayHasKey( 'expires_in', $pair );
		$this->assertSame( TokenStore::ACCESS_TTL, $pair['expires_in'] );
	}

	public function test_issue_returns_granted_scope_verbatim(): void {
		$scope = 'abilities:content:read abilities:content:write';
		$pair  = TokenStore::issue( 'cl_test', 1, $scope, 'https://example.com/wp-json/mcp/mcp-adapter-default-server' );
		$this->assertArrayHasKey( 'scope', $pair );
		$this->assertSame( $scope, $pair['scope'] );
	}

	// -------------------------------------------------------------------------
	// Scope-return policy: stored (expanded) set always returned
	// -------------------------------------------------------------------------

	public function test_scope_returned_is_the_stored_expanded_set(): void {
		// Simulate what AuthorizeRequestValidator does: expand umbrella to granular.
		// The token response must return this expanded set so clients know exactly
		// what the token covers (RFC 6749 §3.3 + §5.1).
		$expanded_scope = implode( ' ', [
			'abilities:read',            // umbrella kept as-is in this test...
			'abilities:content:read',    // ...alongside its expansion
			'abilities:media:read',
		] );

		$pair = TokenStore::issue( 'cl_test', 1, $expanded_scope, 'https://example.com/wp-json/mcp/mcp-adapter-default-server' );

		$this->assertSame( $expanded_scope, $pair['scope'], 'Stored scope must be returned verbatim' );
	}

	// -------------------------------------------------------------------------
	// Exact key set (no extra surprises)
	// -------------------------------------------------------------------------

	public function test_issue_response_has_exactly_five_keys(): void {
		$pair = TokenStore::issue( 'cl_test', 1, 'abilities:content:read', 'https://example.com/wp-json/mcp/mcp-adapter-default-server' );

		$this->assertCount( 5, $pair, 'Issue response must have exactly 5 keys: access_token, token_type, refresh_token, expires_in, scope' );
		$this->assertSame(
			[ 'access_token', 'token_type', 'refresh_token', 'expires_in', 'scope' ],
			array_keys( $pair )
		);
	}
}
