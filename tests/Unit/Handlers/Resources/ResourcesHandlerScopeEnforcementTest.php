<?php
/**
 * Scope enforcement at the resources/read dispatch path (#45).
 *
 * Before the fix: `ResourcesHandler::read_resource` had no reference to
 * `OAuthRequestContext` or `OAuthScopeEnforcer`. A token whose granted
 * scopes did not cover an exposed resource's ability still executed it
 * (under the bound user's WP capabilities) — the H.1.3 enforcer was
 * simply not wired into this handler.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Handlers\Resources
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Handlers\Resources;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthRequestContext;
use WickedEvolutions\McpAdapter\Core\McpServer;
use WickedEvolutions\McpAdapter\Domain\Resources\McpResource;
use WickedEvolutions\McpAdapter\Handlers\Resources\ResourcesHandler;

final class ResourcesHandlerScopeEnforcementTest extends TestCase {

	protected function setUp(): void {
		OAuthRequestContext::reset();
		$GLOBALS['wp_test_abilities'] = array();
	}

	protected function tearDown(): void {
		OAuthRequestContext::reset();
		$GLOBALS['wp_test_abilities'] = array();
	}

	/**
	 * Register a stub ability that records whether execute() was called and
	 * returns a sentinel string. Tests assert against this counter to prove
	 * whether the scope gate short-circuited before execution.
	 */
	private function register_writeable_ability( string $name = 'content/get-secret' ): object {
		$ability = new class( $name, array(
			'category' => 'content',
			'meta'     => array( 'annotations' => array( 'permission' => 'write' ) ),
		) ) extends \WP_Ability {
			public int $execute_calls = 0;
			public function check_permissions( $args = null ) { return true; }
			public function execute( $args = null ) {
				++$this->execute_calls;
				return 'EXECUTED';
			}
		};
		$GLOBALS['wp_test_abilities'][ $name ] = $ability;
		return $ability;
	}

	/** Build a ResourcesHandler whose mcp server returns the given resource. */
	private function handler_with_resource( McpResource $resource ): ResourcesHandler {
		$server = new class( $resource ) extends McpServer {
			private McpResource $stub;
			public function __construct( McpResource $stub ) {
				$this->stub = $stub;
				$this->error_handler = new class implements \WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\Contracts\McpErrorHandlerInterface {
					public function log( string $message, array $context = array(), string $type = 'error' ): void {}
				};
			}
			public function get_resource( string $resource_uri ): ?McpResource {
				return $this->stub;
			}
		};
		return new ResourcesHandler( $server );
	}

	private function set_oauth_request( array $scopes ): void {
		OAuthRequestContext::set( 7, $scopes, 'https://example.com/wp-json/mcp/mcp-adapter-default-server', 'cl_test', 1 );
	}

	public function test_oauth_request_without_required_scope_denies_with_insufficient_scope(): void {
		$ability  = $this->register_writeable_ability( 'content/get-secret' );
		$resource = new McpResource( 'content/get-secret', 'mcp://test/secret' );

		// Token has only `abilities:content:read`; the resource's ability requires
		// `abilities:content:write`. Pre-fix the handler called execute() anyway —
		// the gate must short-circuit before that.
		$this->set_oauth_request( array( 'abilities:content:read' ) );

		$result = $this->handler_with_resource( $resource )->read_resource( array( 'uri' => 'mcp://test/secret' ) );

		$this->assertSame( 0, $ability->execute_calls, 'execute() must not run when scope is denied' );
		$this->assertArrayHasKey( 'error', $result );
		$this->assertSame( 'insufficient_scope', $result['_metadata']['failure_reason'] );
		$this->assertSame( 'abilities:content:write', $result['_metadata']['error_code'] );
		$this->assertSame( 'abilities:content:write', $result['error']['data']['required_scope'] );
		$this->assertArrayNotHasKey( 'contents', $result );
	}

	public function test_non_oauth_request_runs_execute_unchanged(): void {
		// No OAuthRequestContext → enforcer no-ops → execute() must still run.
		// This proves the gate doesn't break the WP-cookie-auth path.
		$ability  = $this->register_writeable_ability( 'content/get-secret' );
		$resource = new McpResource( 'content/get-secret', 'mcp://test/secret' );

		$result = $this->handler_with_resource( $resource )->read_resource( array( 'uri' => 'mcp://test/secret' ) );

		$this->assertSame( 1, $ability->execute_calls );
		$this->assertSame( 'EXECUTED', $result['contents'] );
	}

	public function test_oauth_request_with_required_scope_proceeds_to_execute(): void {
		$ability  = $this->register_writeable_ability( 'content/get-secret' );
		$resource = new McpResource( 'content/get-secret', 'mcp://test/secret' );
		$this->set_oauth_request( array( 'abilities:content:write' ) );

		$result = $this->handler_with_resource( $resource )->read_resource( array( 'uri' => 'mcp://test/secret' ) );

		$this->assertSame( 1, $ability->execute_calls );
		$this->assertSame( 'EXECUTED', $result['contents'] );
	}
}
