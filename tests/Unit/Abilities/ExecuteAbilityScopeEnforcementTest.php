<?php
/**
 * Scope enforcement at the `mcp-adapter/execute-ability` meta-tool's
 * per-underlying-ability dispatch (#39, #45).
 *
 * Pre-fix: `ExecuteAbilityAbility::execute()` resolved an inner ability
 * via `wp_get_ability($ability_name)` and called `$inner->execute()`
 * without consulting OAuth scope. The outer dispatch only saw the
 * meta-tool itself; the inner ability ran under the bound user's WP
 * caps regardless of granted scope.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Abilities
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Abilities;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Abilities\ExecuteAbilityAbility;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthRequestContext;

final class ExecuteAbilityScopeEnforcementTest extends TestCase {

	protected function setUp(): void {
		OAuthRequestContext::reset();
		$GLOBALS['wp_test_abilities']    = array();
		$GLOBALS['wp_test_current_user'] = 7;
		$GLOBALS['wp_test_caps']         = array( 'read' => true );
	}

	protected function tearDown(): void {
		OAuthRequestContext::reset();
		$GLOBALS['wp_test_abilities']    = array();
		unset( $GLOBALS['wp_test_current_user'] );
		unset( $GLOBALS['wp_test_caps'] );
	}

	private function register_inner_ability( string $name = 'users/create' ): object {
		$ability = new class( $name, array(
			'category' => 'users',
			'meta'     => array(
				'annotations' => array( 'permission' => 'write' ),
				'mcp'         => array( 'public' => true ),
			),
		) ) extends \WP_Ability {
			public int $execute_calls = 0;
			public function check_permissions( $args = null ) { return true; }
			public function get_input_schema() { return array(); }
			public function execute( $args = null ) {
				++$this->execute_calls;
				return array( 'created' => true );
			}
		};
		$GLOBALS['wp_test_abilities'][ $name ] = $ability;
		return $ability;
	}

	private function set_oauth_request( array $scopes ): void {
		OAuthRequestContext::set( 7, $scopes, 'https://example.com/wp-json/mcp/mcp-adapter-default-server', 'cl_test', 1 );
	}

	public function test_inner_ability_blocked_when_token_lacks_inner_scope(): void {
		$inner = $this->register_inner_ability( 'users/create' );

		// Token has the outer meta-tool scope (read on mcp-adapter) but NOT the
		// inner sensitive `abilities:users:write`.
		$this->set_oauth_request( array( 'abilities:mcp-adapter:read' ) );

		$result = ExecuteAbilityAbility::execute( array(
			'ability_name' => 'users/create',
			'parameters'   => array(),
		) );

		$this->assertSame( 0, $inner->execute_calls, 'inner execute() must not run on scope deny' );
		$this->assertFalse( $result['success'] );
		$this->assertSame( 'insufficient_scope', $result['error_code'] );
		$this->assertSame( 'abilities:users:write', $result['required_scope'] );
	}

	public function test_inner_ability_runs_when_token_has_explicit_inner_scope(): void {
		$inner = $this->register_inner_ability( 'users/create' );

		$this->set_oauth_request( array( 'abilities:mcp-adapter:read', 'abilities:users:write' ) );

		$result = ExecuteAbilityAbility::execute( array(
			'ability_name' => 'users/create',
			'parameters'   => array(),
		) );

		$this->assertSame( 1, $inner->execute_calls );
		$this->assertTrue( $result['success'] );
		$this->assertSame( array( 'created' => true ), $result['data'] );
	}

	public function test_non_oauth_request_runs_inner_ability(): void {
		// No OAuthRequestContext → enforcer no-ops → inner ability runs under WP caps.
		$inner = $this->register_inner_ability( 'users/create' );

		$result = ExecuteAbilityAbility::execute( array(
			'ability_name' => 'users/create',
			'parameters'   => array(),
		) );

		$this->assertSame( 1, $inner->execute_calls );
		$this->assertTrue( $result['success'] );
	}
}
