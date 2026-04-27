<?php
/**
 * Scope enforcement at the prompts/get dispatch path (#40, #45).
 *
 * Pre-fix: `PromptsHandler::get_prompt` had no reference to
 * `OAuthRequestContext` or `OAuthScopeEnforcer`. Both the ability-based
 * and builder-based execution paths called `execute()` / `execute_direct()`
 * without consulting the granted scope set.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Handlers\Prompts
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Handlers\Prompts;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthRequestContext;
use WickedEvolutions\McpAdapter\Core\McpServer;
use WickedEvolutions\McpAdapter\Domain\Prompts\McpPrompt;
use WickedEvolutions\McpAdapter\Handlers\Prompts\PromptsHandler;

final class PromptsHandlerScopeEnforcementTest extends TestCase {

	protected function setUp(): void {
		OAuthRequestContext::reset();
		$GLOBALS['wp_test_abilities'] = array();
	}

	protected function tearDown(): void {
		OAuthRequestContext::reset();
		$GLOBALS['wp_test_abilities'] = array();
	}

	private function register_writeable_ability( string $name = 'content/draft-prompt' ): object {
		$ability = new class( $name, array(
			'category' => 'content',
			'meta'     => array( 'annotations' => array( 'permission' => 'write' ) ),
		) ) extends \WP_Ability {
			public int $execute_calls = 0;
			public function check_permissions( $args = null ) { return true; }
			public function execute( $args = null ) {
				++$this->execute_calls;
				return array( 'messages' => array( array( 'role' => 'user', 'content' => 'ok' ) ) );
			}
		};
		$GLOBALS['wp_test_abilities'][ $name ] = $ability;
		return $ability;
	}

	private function handler_with_prompt( McpPrompt $prompt ): PromptsHandler {
		$server = new class( $prompt ) extends McpServer {
			private McpPrompt $stub;
			public function __construct( McpPrompt $stub ) {
				$this->stub = $stub;
				$this->error_handler = new class implements \WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\Contracts\McpErrorHandlerInterface {
					public function log( string $message, array $context = array(), string $type = 'error' ): void {}
				};
			}
			public function get_prompt( string $prompt_name ): ?McpPrompt {
				return $this->stub;
			}
		};
		return new PromptsHandler( $server );
	}

	private function set_oauth_request( array $scopes ): void {
		OAuthRequestContext::set( 7, $scopes, 'https://example.com/wp-json/mcp/mcp-adapter-default-server', 'cl_test', 1 );
	}

	// ---------------------------------------------------------------------
	// Ability-based path
	// ---------------------------------------------------------------------

	public function test_ability_based_oauth_without_scope_denies(): void {
		$ability = $this->register_writeable_ability( 'content/draft-prompt' );
		$prompt  = new McpPrompt( 'content/draft-prompt', 'draft' );

		$this->set_oauth_request( array( 'abilities:content:read' ) );

		$result = $this->handler_with_prompt( $prompt )->get_prompt( array( 'name' => 'draft' ) );

		$this->assertSame( 0, $ability->execute_calls );
		$this->assertSame( 'insufficient_scope', $result['_metadata']['failure_reason'] );
		$this->assertSame( 'abilities:content:write', $result['_metadata']['error_code'] );
		$this->assertFalse( $result['_metadata']['is_builder'] );
	}

	public function test_ability_based_oauth_with_required_scope_runs_execute(): void {
		$ability = $this->register_writeable_ability( 'content/draft-prompt' );
		$prompt  = new McpPrompt( 'content/draft-prompt', 'draft' );

		$this->set_oauth_request( array( 'abilities:content:write' ) );

		$result = $this->handler_with_prompt( $prompt )->get_prompt( array( 'name' => 'draft' ) );

		$this->assertSame( 1, $ability->execute_calls );
		$this->assertArrayNotHasKey( 'error', $result );
	}

	public function test_ability_based_non_oauth_runs_execute(): void {
		$ability = $this->register_writeable_ability( 'content/draft-prompt' );
		$prompt  = new McpPrompt( 'content/draft-prompt', 'draft' );

		$result = $this->handler_with_prompt( $prompt )->get_prompt( array( 'name' => 'draft' ) );

		$this->assertSame( 1, $ability->execute_calls );
		$this->assertArrayNotHasKey( 'error', $result );
	}

	// ---------------------------------------------------------------------
	// Builder-based path
	// ---------------------------------------------------------------------

	private function builder_prompt(): McpPrompt {
		// Anonymous subclass: is_builder_based() => true, with permission/execute stubs
		// that record their invocation count.
		return new class( 'unused', 'help-prompt' ) extends McpPrompt {
			public int $execute_direct_calls = 0;
			public function is_builder_based(): bool { return true; }
			public function check_permission_direct( array $arguments ): bool { return true; }
			public function execute_direct( array $arguments ): array {
				++$this->execute_direct_calls;
				return array( 'messages' => array( array( 'role' => 'user', 'content' => 'help' ) ) );
			}
		};
	}

	public function test_builder_oauth_without_baseline_scope_denies(): void {
		$prompt = $this->builder_prompt();

		// Token grants a different scope; the builder requires `abilities:mcp-adapter:read`.
		$this->set_oauth_request( array( 'abilities:content:read' ) );

		$result = $this->handler_with_prompt( $prompt )->get_prompt( array( 'name' => 'help-prompt' ) );

		$this->assertSame( 0, $prompt->execute_direct_calls );
		$this->assertSame( 'insufficient_scope', $result['_metadata']['failure_reason'] );
		$this->assertSame( 'abilities:mcp-adapter:read', $result['_metadata']['error_code'] );
		$this->assertTrue( $result['_metadata']['is_builder'] );
	}

	public function test_builder_oauth_with_baseline_scope_runs(): void {
		$prompt = $this->builder_prompt();
		$this->set_oauth_request( array( 'abilities:mcp-adapter:read' ) );

		$result = $this->handler_with_prompt( $prompt )->get_prompt( array( 'name' => 'help-prompt' ) );

		$this->assertSame( 1, $prompt->execute_direct_calls );
		$this->assertArrayNotHasKey( 'error', $result );
	}

	public function test_builder_non_oauth_runs(): void {
		$prompt = $this->builder_prompt();

		$result = $this->handler_with_prompt( $prompt )->get_prompt( array( 'name' => 'help-prompt' ) );

		$this->assertSame( 1, $prompt->execute_direct_calls );
		$this->assertArrayNotHasKey( 'error', $result );
	}
}
