<?php
/**
 * #90: Path-style multisite authorize-endpoint routing.
 *
 * Pre-fix: AuthorizationServer::intercept_pre_wp_routes() only dispatched the
 * exact root path '/oauth/authorize'. Discovery metadata for a path-style
 * subsite (e.g. /sub2) advertises https://example.com/sub2/oauth/authorize, so
 * any client following discovery fell through to WordPress and 404'd before
 * consent could render. The authorize-endpoint helpers (self-post URL, login
 * redirect, resource indicator) also lacked subsite-prefix awareness.
 *
 * After fix:
 *   1. The interceptor matches any path ending in '/oauth/authorize' and
 *      passes the leading prefix (or null for root) into AuthorizeEndpoint.
 *   2. AuthorizeEndpoint::self_url($prefix) and resource_indicator($prefix)
 *      build URLs that match what discovery advertised for the same subsite.
 *
 * Tests here pin:
 *   - AuthorizationServer::extract_authorize_path_prefix() boundary cases
 *   - AuthorizeEndpoint::self_url() with and without prefix
 *   - AuthorizeEndpoint::resource_indicator() with and without prefix
 *
 * End-to-end path-style multisite verification is NOT a release gate per the
 * Public Alpha Hardening sprint plan §3 alpha-scope lock — alpha is
 * subdomain-style only. Path-style is named as a known limitation in the
 * v1.4.5 CHANGELOG; building a path-style multisite test environment is a
 * follow-up infrastructure task. This file's coverage is the intentional
 * release gate for #90.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationServer;
use WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints\AuthorizeEndpoint;

final class PathStyleMultisiteAuthorizeRoutingTest extends TestCase {

	protected function setUp(): void {
		unset( $_SERVER['HTTP_HOST'], $_SERVER['HTTPS'], $_SERVER['HTTP_X_FORWARDED_PROTO'] );
		$GLOBALS['wp_test_home_url'] = 'https://example.com';
	}

	protected function tearDown(): void {
		unset( $GLOBALS['wp_test_home_url'] );
	}

	// -------------------------------------------------------------------------
	// extract_authorize_path_prefix() — boundary cases
	// -------------------------------------------------------------------------

	/** Exact root path → null prefix (single-site / subdomain-style multisite). */
	public function test_extract_authorize_prefix_root_path_yields_null(): void {
		$this->assertNull(
			AuthorizationServer::extract_authorize_path_prefix( '/oauth/authorize' )
		);
	}

	/** Single-segment subsite path → prefix '/sub2'. */
	public function test_extract_authorize_prefix_single_segment(): void {
		$this->assertSame(
			'/sub2',
			AuthorizationServer::extract_authorize_path_prefix( '/sub2/oauth/authorize' )
		);
	}

	/** Multi-segment subsite path → prefix '/team/blog' (consistent with discovery side). */
	public function test_extract_authorize_prefix_multi_segment(): void {
		$this->assertSame(
			'/team/blog',
			AuthorizationServer::extract_authorize_path_prefix( '/team/blog/oauth/authorize' )
		);
	}

	/**
	 * '/oauth/authorizeextra' must NOT match — str_ends_with anchor is
	 * '/oauth/authorize' (with leading slash), so suffix-substring tricks
	 * can't widen the dispatch surface.
	 */
	public function test_extract_authorize_prefix_suffix_substring_does_not_match(): void {
		$this->assertNull(
			AuthorizationServer::extract_authorize_path_prefix( '/oauth/authorizeextra' )
		);
	}

	/**
	 * Trailing slash form ('/oauth/authorize/') is NOT matched — discovery
	 * metadata advertises no trailing slash, and the interceptor doesn't
	 * normalize. Pinned so any future normalization change surfaces here.
	 */
	public function test_extract_authorize_prefix_trailing_slash_does_not_match(): void {
		$this->assertNull(
			AuthorizationServer::extract_authorize_path_prefix( '/oauth/authorize/' )
		);
	}

	/**
	 * Path missing the leading slash ('oauth/authorize') is malformed; head
	 * before the suffix is empty so it normalizes to root → null. Either
	 * "null (no match)" or "null (root match)" is acceptable here; pinned to
	 * the actual current behavior so changes are visible.
	 */
	public function test_extract_authorize_prefix_no_leading_slash_yields_null(): void {
		$this->assertNull(
			AuthorizationServer::extract_authorize_path_prefix( 'oauth/authorize' )
		);
	}

	/** Unrelated paths return null. */
	public function test_extract_authorize_prefix_unrelated_path_yields_null(): void {
		$this->assertNull(
			AuthorizationServer::extract_authorize_path_prefix( '/some-other-path' )
		);
	}

	/**
	 * Prefix that itself contains '/oauth' is accepted — the helper's
	 * contract is purely structural ("split on the last '/oauth/authorize'
	 * suffix"). Whether the prefix actually maps to a real subsite is a
	 * downstream concern (WP resolves blog ID from host+path). Pinned so the
	 * security boundary is explicit.
	 */
	public function test_extract_authorize_prefix_prefix_containing_oauth_segment(): void {
		$this->assertSame(
			'/oauth',
			AuthorizationServer::extract_authorize_path_prefix( '/oauth/oauth/authorize' )
		);
	}

	// -------------------------------------------------------------------------
	// AuthorizeEndpoint::self_url() — must include the prefix when supplied
	// -------------------------------------------------------------------------

	public function test_self_url_without_prefix_returns_root_authorize_url(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$self_url = $this->call_self_url( null );
		$this->assertSame( 'http://example.com/oauth/authorize', $self_url );
	}

	public function test_self_url_with_path_prefix_includes_prefix(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$self_url = $this->call_self_url( '/sub2' );
		$this->assertSame( 'http://example.com/sub2/oauth/authorize', $self_url );
	}

	public function test_self_url_with_multi_segment_prefix(): void {
		$_SERVER['HTTP_HOST'] = 'example.com';
		$self_url = $this->call_self_url( '/team/blog' );
		$this->assertSame( 'http://example.com/team/blog/oauth/authorize', $self_url );
	}

	// -------------------------------------------------------------------------
	// AuthorizeEndpoint::resource_indicator() — must mirror discovery URL
	// when a prefix is supplied; preserve rest_url() fallback when null.
	// -------------------------------------------------------------------------

	public function test_resource_indicator_without_prefix_uses_rest_url(): void {
		// rest_url() stub returns wp_test_home_url . '/wp-json/' . path.
		$indicator = $this->call_resource_indicator( null );
		$this->assertSame(
			'https://example.com/wp-json/mcp/abilities-mcp-adapter-default-server',
			$indicator
		);
	}

	public function test_resource_indicator_with_path_prefix_uses_discovery_resource_url(): void {
		// DiscoveryEndpoints::resource_url('/sub2') derives from HTTP_HOST,
		// not wp_test_home_url, because pre-WP it can't trust rest_url().
		$_SERVER['HTTP_HOST'] = 'example.com';
		$indicator = $this->call_resource_indicator( '/sub2' );
		$this->assertSame(
			'http://example.com/sub2/wp-json/mcp/abilities-mcp-adapter-default-server',
			$indicator
		);
	}

	public function test_resource_indicator_empty_prefix_treated_as_no_prefix(): void {
		// Empty string is treated the same as null — falls back to rest_url().
		$indicator = $this->call_resource_indicator( '' );
		$this->assertSame(
			'https://example.com/wp-json/mcp/abilities-mcp-adapter-default-server',
			$indicator
		);
	}

	// -------------------------------------------------------------------------
	// Reflection helpers — self_url and resource_indicator are private.
	// -------------------------------------------------------------------------

	private function call_self_url( ?string $path_prefix ): string {
		$ref = new \ReflectionClass( AuthorizeEndpoint::class );
		$m   = $ref->getMethod( 'self_url' );
		return (string) $m->invoke( null, $path_prefix );
	}

	private function call_resource_indicator( ?string $path_prefix ): string {
		$ref = new \ReflectionClass( AuthorizeEndpoint::class );
		$m   = $ref->getMethod( 'resource_indicator' );
		return (string) $m->invoke( null, $path_prefix );
	}
}
