<?php
/**
 * Pin McpResourcePath constant values (#54).
 *
 * The whole point of the lift is that all callsites read the same value.
 * If the canonical constants change, the tests that pin downstream URLs
 * (PathStyleMultisiteDiscoveryTest, AuthenticateBearerNarrowsToMcpResourceTest,
 * etc.) will fail in lockstep — and so will this test, surfacing the rename
 * intent at exactly one place.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\McpResourcePath;

final class McpResourcePathTest extends TestCase {

	public function test_rest_namespace_is_mcp(): void {
		$this->assertSame( 'mcp', McpResourcePath::REST_NAMESPACE );
	}

	public function test_route_is_mcp_adapter_default_server(): void {
		$this->assertSame( 'mcp-adapter-default-server', McpResourcePath::ROUTE );
	}

	public function test_path_is_namespace_slash_route_with_no_leading_slash(): void {
		$this->assertSame( 'mcp/mcp-adapter-default-server', McpResourcePath::PATH );
	}

	public function test_leading_slash_path_has_leading_slash(): void {
		$this->assertSame( '/mcp/mcp-adapter-default-server', McpResourcePath::LEADING_SLASH_PATH );
		$this->assertSame( '/' . McpResourcePath::PATH, McpResourcePath::LEADING_SLASH_PATH );
	}
}
