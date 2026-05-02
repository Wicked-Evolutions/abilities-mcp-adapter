<?php
/**
 * Regression for #53: `AuthorizationServer::authenticate_bearer()`'s
 * Authorization-header probe must record only when the request hits the
 * MCP namespace `/wp-json/mcp/`. The stale `/wp-json/abilities-mcp-adapter/`
 * namespace has no routes registered and matching it was silently dead —
 * the diagnostic seam recorded zero data despite firing on every REST hit
 * to that prefix.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Admin\Bridges\AuthHeaderProbe;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationServer;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthRequestContext;

if ( ! defined( 'REST_REQUEST' ) ) {
	define( 'REST_REQUEST', true );
}

final class AuthHeaderProbeNamespaceGateTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		AuthHeaderProbe::clear();
		OAuthRequestContext::reset();
	}

	protected function tearDown(): void {
		AuthHeaderProbe::clear();
		OAuthRequestContext::reset();
		unset( $_SERVER['REQUEST_URI'] );
		unset( $_SERVER['HTTP_AUTHORIZATION'] );
		parent::tearDown();
	}

	public function test_probe_records_on_mcp_namespace_request(): void {
		$_SERVER['REQUEST_URI']        = '/wp-json/mcp/mcp-adapter-default-server';
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer some-token';

		AuthorizationServer::authenticate_bearer( false );

		$state = get_option( AuthHeaderProbe::OPTION );
		$this->assertIsArray( $state, 'Probe must record an observation on /wp-json/mcp/ requests' );
		$this->assertCount( 1, $state['observations'] ?? array() );
		$this->assertSame( 1, $state['observations'][0], 'Bearer header presence must be recorded as 1' );
	}

	public function test_probe_does_not_record_on_stale_abilities_mcp_adapter_namespace(): void {
		// The whole point of #53: pre-fix, this URI matched the OR branch and
		// the probe recorded against a namespace that holds no real routes.
		// Post-fix, the OR branch is gone and the probe stays silent here.
		$_SERVER['REQUEST_URI']        = '/wp-json/abilities-mcp-adapter/anything';
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer some-token';

		AuthorizationServer::authenticate_bearer( false );

		$this->assertFalse(
			get_option( AuthHeaderProbe::OPTION, false ),
			'Probe must not record on the stale /wp-json/abilities-mcp-adapter/ namespace'
		);
	}

	public function test_probe_does_not_record_on_unrelated_rest_routes(): void {
		$_SERVER['REQUEST_URI']        = '/wp-json/wp/v2/users';
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer some-token';

		AuthorizationServer::authenticate_bearer( false );

		$this->assertFalse(
			get_option( AuthHeaderProbe::OPTION, false ),
			'Probe must not record on unrelated REST routes'
		);
	}

	public function test_probe_records_zero_when_authorization_header_absent(): void {
		$_SERVER['REQUEST_URI'] = '/wp-json/mcp/mcp-adapter-default-server';
		// No HTTP_AUTHORIZATION set.

		AuthorizationServer::authenticate_bearer( false );

		$state = get_option( AuthHeaderProbe::OPTION );
		$this->assertIsArray( $state );
		$this->assertSame( 0, $state['observations'][0] ?? null,
			'Missing Authorization header must be recorded as 0'
		);
	}
}
