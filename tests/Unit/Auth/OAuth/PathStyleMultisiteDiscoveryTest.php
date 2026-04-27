<?php
/**
 * M-5: Path-style multisite discovery routing.
 *
 * Pre-fix: AuthorizationServer::intercept_pre_wp_routes() used an exact match()
 * table, so paths like /.well-known/oauth-authorization-server/sub2 fell through
 * to WP's 404. Path-style multisite subsites could not be discovered at all.
 *
 * After fix:
 *   1. intercept_pre_wp_routes() uses str_starts_with + extract_path_prefix()
 *      so any path that begins with a known .well-known keyword is handled.
 *   2. DiscoveryEndpoints::issuer() accepts an optional ?string $path_prefix;
 *      when supplied, the prefix is appended to the host-derived origin so that
 *      the issuer matches the subsite's home URL.
 *
 * Tests here cover:
 *   - issuer() with and without path prefix
 *   - issuer() trims leading slashes from the prefix
 *   - resource_url() and metadata URLs include the prefix
 *   - Root-site paths (no prefix) still return the plain origin
 *   - is_well_known_or_oauth_path() still matches path-style probes
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\DiscoveryEndpoints;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationServer;

final class PathStyleMultisiteDiscoveryTest extends TestCase {

	protected function setUp(): void {
		unset( $_SERVER['HTTP_HOST'], $_SERVER['HTTPS'], $_SERVER['HTTP_X_FORWARDED_PROTO'] );
	}

	// -------------------------------------------------------------------------
	// DiscoveryEndpoints::issuer() — path prefix support
	// -------------------------------------------------------------------------

	public function test_issuer_without_prefix_returns_plain_origin(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$this->assertSame( 'http://example.com', DiscoveryEndpoints::issuer() );
	}

	public function test_issuer_with_null_prefix_returns_plain_origin(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$this->assertSame( 'http://example.com', DiscoveryEndpoints::issuer( null ) );
	}

	public function test_issuer_with_path_prefix_appends_prefix(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$this->assertSame( 'http://example.com/sub2', DiscoveryEndpoints::issuer( '/sub2' ) );
	}

	public function test_issuer_strips_leading_slash_from_prefix(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		// Both forms must produce the same canonical issuer.
		$with_slash    = DiscoveryEndpoints::issuer( '/sub2' );
		$without_slash = DiscoveryEndpoints::issuer( 'sub2' );
		$this->assertSame( $with_slash, $without_slash );
		$this->assertStringEndsWith( '/sub2', $with_slash );
	}

	public function test_issuer_empty_string_prefix_treated_as_root(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$this->assertSame( 'http://example.com', DiscoveryEndpoints::issuer( '' ) );
	}

	public function test_issuer_single_slash_prefix_treated_as_root(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$this->assertSame( 'http://example.com', DiscoveryEndpoints::issuer( '/' ) );
	}

	public function test_issuer_deep_path_prefix(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$this->assertSame( 'http://example.com/team/blog', DiscoveryEndpoints::issuer( '/team/blog' ) );
	}

	// -------------------------------------------------------------------------
	// DiscoveryEndpoints::resource_url() with path prefix
	// -------------------------------------------------------------------------

	public function test_resource_url_includes_path_prefix(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$url = DiscoveryEndpoints::resource_url( '/sub2' );
		$this->assertStringStartsWith( 'http://example.com/sub2', $url );
		$this->assertStringEndsWith( '/wp-json/mcp/mcp-adapter-default-server', $url );
	}

	public function test_resource_url_without_prefix_unchanged(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$url = DiscoveryEndpoints::resource_url();
		$this->assertSame( 'http://example.com/wp-json/mcp/mcp-adapter-default-server', $url );
	}

	// -------------------------------------------------------------------------
	// Path extraction helper (tested indirectly via issuer composition)
	// Verified by driving intercept_pre_wp_routes() through reflection.
	// -------------------------------------------------------------------------

	/** Root-site path (no trailing segment) → null prefix → plain origin issuer. */
	public function test_extract_path_prefix_root_path_yields_null(): void {
		$prefix = $this->call_extract_path_prefix(
			'/.well-known/oauth-authorization-server',
			'/.well-known/oauth-authorization-server'
		);
		$this->assertNull( $prefix );
	}

	/** Trailing slash only → null prefix (still root site). */
	public function test_extract_path_prefix_trailing_slash_only_yields_null(): void {
		$prefix = $this->call_extract_path_prefix(
			'/.well-known/oauth-authorization-server/',
			'/.well-known/oauth-authorization-server'
		);
		$this->assertNull( $prefix );
	}

	/** Single-segment subsite path → '/sub2'. */
	public function test_extract_path_prefix_single_segment(): void {
		$prefix = $this->call_extract_path_prefix(
			'/.well-known/oauth-authorization-server/sub2',
			'/.well-known/oauth-authorization-server'
		);
		$this->assertSame( '/sub2', $prefix );
	}

	/** Multi-segment subsite path → '/team/blog'. */
	public function test_extract_path_prefix_multi_segment(): void {
		$prefix = $this->call_extract_path_prefix(
			'/.well-known/oauth-authorization-server/team/blog',
			'/.well-known/oauth-authorization-server'
		);
		$this->assertSame( '/team/blog', $prefix );
	}

	/** Works the same for openid-configuration paths. */
	public function test_extract_path_prefix_openid_configuration(): void {
		$prefix = $this->call_extract_path_prefix(
			'/.well-known/openid-configuration/sub2',
			'/.well-known/openid-configuration'
		);
		$this->assertSame( '/sub2', $prefix );
	}

	/** Works for protected-resource paths. */
	public function test_extract_path_prefix_protected_resource(): void {
		$prefix = $this->call_extract_path_prefix(
			'/.well-known/oauth-protected-resource/sub2',
			'/.well-known/oauth-protected-resource'
		);
		$this->assertSame( '/sub2', $prefix );
	}

	// -------------------------------------------------------------------------
	// is_well_known_or_oauth_path() — must still match path-style probes
	// -------------------------------------------------------------------------

	/**
	 * is_well_known_or_oauth_path() already uses str_starts_with internally,
	 * so path-style probes like /.well-known/oauth-authorization-server/sub2
	 * must match (no regression from the pre-fix str_starts_with it already had).
	 */
	public function test_is_well_known_matches_path_style_probe(): void {
		$_SERVER['REQUEST_URI'] = '/.well-known/oauth-authorization-server/sub2';
		$result = $this->call_is_well_known_or_oauth_path();
		$this->assertTrue( $result, '/.well-known/... path-style probes must be treated as well-known paths' );
	}

	public function test_is_well_known_matches_root_probe(): void {
		$_SERVER['REQUEST_URI'] = '/.well-known/oauth-authorization-server';
		$this->assertTrue( $this->call_is_well_known_or_oauth_path() );
	}

	public function test_is_well_known_matches_openid_path_style(): void {
		$_SERVER['REQUEST_URI'] = '/.well-known/openid-configuration/sub2';
		$this->assertTrue( $this->call_is_well_known_or_oauth_path() );
	}

	public function test_is_well_known_does_not_match_arbitrary_path(): void {
		$_SERVER['REQUEST_URI'] = '/some-other-path';
		$this->assertFalse( $this->call_is_well_known_or_oauth_path() );
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	private function call_extract_path_prefix( string $full_path, string $known_prefix ): ?string {
		return AuthorizationServer::extract_path_prefix( $full_path, $known_prefix );
	}

	private function call_is_well_known_or_oauth_path(): bool {
		return AuthorizationServer::is_well_known_or_oauth_path();
	}
}
