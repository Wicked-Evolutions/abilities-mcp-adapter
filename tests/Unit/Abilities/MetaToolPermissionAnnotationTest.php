<?php
/**
 * #42: meta-tool dispatchers (`mcp-adapter/execute-ability`,
 * `mcp-adapter/batch-execute`) had `destructive=true` annotations, which
 * `PermissionManager::get_permission` mapped to `delete`. That meant a
 * token would need `abilities:mcp-adapter:delete` (a sensitive scope —
 * never implied by any umbrella) just to read via the dispatcher. The
 * dispatchers themselves are not destructive operations; per-underlying
 * scope checks (added in #45) carry the actual authorization weight.
 *
 * After the fix: explicit `permission => read` annotation overrides the
 * destructive-true derivation in PermissionManager priority 1.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Abilities
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Abilities;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Abilities\BatchExecuteAbility;
use WickedEvolutions\McpAdapter\Abilities\ExecuteAbilityAbility;
use WickedEvolutions\McpAdapter\Admin\PermissionManager;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthScopeEnforcer;

final class MetaToolPermissionAnnotationTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_abilities'] = array();
	}

	protected function tearDown(): void {
		$GLOBALS['wp_test_abilities'] = array();
	}

	public function test_execute_ability_register_resolves_to_read_not_delete(): void {
		ExecuteAbilityAbility::register();
		$ability = wp_get_ability( 'mcp-adapter/execute-ability' );
		$this->assertNotNull( $ability );

		$this->assertSame( 'read', PermissionManager::get_permission( $ability ) );
		$this->assertSame( 'abilities:mcp-adapter:read', OAuthScopeEnforcer::required_scope_for( $ability ) );
	}

	public function test_batch_execute_register_resolves_to_read_not_delete(): void {
		BatchExecuteAbility::register();
		$ability = wp_get_ability( 'mcp-adapter/batch-execute' );
		$this->assertNotNull( $ability );

		$this->assertSame( 'read', PermissionManager::get_permission( $ability ) );
		$this->assertSame( 'abilities:mcp-adapter:read', OAuthScopeEnforcer::required_scope_for( $ability ) );
	}

	/**
	 * Sanity: the same ability without the explicit `permission => read`
	 * override would resolve to `delete` from priority-2 derivation. Locks
	 * in why the explicit override is required and prevents accidental
	 * reversion.
	 */
	public function test_destructive_alone_would_resolve_to_delete(): void {
		$ability = new \WP_Ability( 'regression/destructive', array(
			'category' => 'mcp-adapter',
			'meta'     => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => true,
					'idempotent'  => false,
				),
			),
		) );

		$this->assertSame( 'delete', PermissionManager::get_permission( $ability ) );
	}

	/**
	 * Lock-in: the destructive=true MCP-level annotation is preserved (clients
	 * still see the dispatcher as destructive). Only the OAuth scope mapping
	 * changes via the new `permission => read` override.
	 */
	public function test_meta_tools_keep_destructive_client_annotation(): void {
		ExecuteAbilityAbility::register();
		BatchExecuteAbility::register();

		foreach ( array( 'mcp-adapter/execute-ability', 'mcp-adapter/batch-execute' ) as $name ) {
			$meta = wp_get_ability( $name )->get_meta();
			$this->assertTrue(
				$meta['annotations']['destructive'] ?? false,
				"$name should retain destructive=true for client display"
			);
		}
	}
}
