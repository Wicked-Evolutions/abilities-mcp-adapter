<?php
/**
 * Tests for the global oauth_is_mcp_resource_request() helper (C-1, H.1.2).
 *
 * The helper gates Bearer authentication: only requests that target the MCP
 * resource endpoint (/wp-json/mcp/mcp-adapter-default-server) may
 * be authenticated by an OAuth bearer token. Every other URI must return
 * false so determine_current_user can no-op.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;

final class OAuthIsMcpResourceRequestTest extends TestCase {

	protected function tearDown(): void {
		unset( $_SERVER['REQUEST_URI'] );
	}

	public function test_unset_request_uri_returns_false(): void {
		unset( $_SERVER['REQUEST_URI'] );
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_empty_request_uri_returns_false(): void {
		$_SERVER['REQUEST_URI'] = '';
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_non_string_request_uri_returns_false(): void {
		$_SERVER['REQUEST_URI'] = false;
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_root_returns_false(): void {
		$_SERVER['REQUEST_URI'] = '/';
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_wp_v2_users_returns_false(): void {
		// C-1: a token issued for the MCP resource MUST NOT authenticate
		// the user on /wp-json/wp/v2/users.
		$_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/users';
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_wp_v2_posts_returns_false(): void {
		$_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts?per_page=10';
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_wp_v2_plugins_returns_false(): void {
		$_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/plugins';
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_oauth_token_endpoint_returns_false(): void {
		// /wp-json/mcp/oauth/token is in the MCP namespace but is not the
		// MCP resource — bearer auth must not fire here.
		$_SERVER['REQUEST_URI'] = '/wp-json/mcp/oauth/token';
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_oauth_register_endpoint_returns_false(): void {
		$_SERVER['REQUEST_URI'] = '/wp-json/mcp/oauth/register';
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_oauth_revoke_endpoint_returns_false(): void {
		$_SERVER['REQUEST_URI'] = '/wp-json/mcp/oauth/revoke';
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_pretty_permalink_mcp_resource_returns_true(): void {
		$_SERVER['REQUEST_URI'] = '/wp-json/mcp/mcp-adapter-default-server';
		$this->assertTrue( \oauth_is_mcp_resource_request() );
	}

	public function test_pretty_permalink_mcp_resource_with_query_returns_true(): void {
		$_SERVER['REQUEST_URI'] = '/wp-json/mcp/mcp-adapter-default-server?foo=bar';
		$this->assertTrue( \oauth_is_mcp_resource_request() );
	}

	public function test_pretty_permalink_mcp_resource_with_subpath_returns_true(): void {
		// Defensive: should the MCP server ever expose a sub-resource, the
		// gate must still admit it. The token's resource binding still
		// covers the canonical endpoint.
		$_SERVER['REQUEST_URI'] = '/wp-json/mcp/mcp-adapter-default-server/anything';
		$this->assertTrue( \oauth_is_mcp_resource_request() );
	}

	public function test_plain_permalink_mcp_resource_returns_true(): void {
		$_SERVER['REQUEST_URI'] = '/index.php?rest_route=/mcp/mcp-adapter-default-server';
		$this->assertTrue( \oauth_is_mcp_resource_request() );
	}

	public function test_plain_permalink_other_route_returns_false(): void {
		$_SERVER['REQUEST_URI'] = '/index.php?rest_route=/wp/v2/users';
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_resource_prefix_with_extra_chars_is_not_a_match(): void {
		// /wp-json/mcp/mcp-adapter-default-server-extra must not match the
		// canonical /wp-json/mcp/mcp-adapter-default-server prefix.
		$_SERVER['REQUEST_URI'] = '/wp-json/mcp/mcp-adapter-default-server-extra';
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_oauth_authorize_returns_false(): void {
		// /oauth/authorize is intercepted pre-WP and is not a REST route at all.
		$_SERVER['REQUEST_URI'] = '/oauth/authorize?response_type=code&client_id=abc';
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_well_known_resource_metadata_returns_false(): void {
		$_SERVER['REQUEST_URI'] = '/.well-known/oauth-protected-resource';
		$this->assertFalse( \oauth_is_mcp_resource_request() );
	}

	public function test_subdir_install_uses_rest_url_prefix(): void {
		// Multisite path-based / subdirectory installs.
		$prev_home = $GLOBALS['wp_test_home_url'] ?? null;
		$GLOBALS['wp_test_home_url'] = 'https://example.com/sub';
		try {
			$_SERVER['REQUEST_URI'] = '/sub/wp-json/mcp/mcp-adapter-default-server';
			$this->assertTrue( \oauth_is_mcp_resource_request() );

			$_SERVER['REQUEST_URI'] = '/wp-json/mcp/mcp-adapter-default-server';
			$this->assertFalse(
				\oauth_is_mcp_resource_request(),
				'subdir install must not match the bare /wp-json/ path'
			);
		} finally {
			if ( null === $prev_home ) {
				unset( $GLOBALS['wp_test_home_url'] );
			} else {
				$GLOBALS['wp_test_home_url'] = $prev_home;
			}
		}
	}
}
