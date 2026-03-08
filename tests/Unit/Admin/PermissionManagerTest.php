<?php
/**
 * Tests for PermissionManager.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

namespace WickedEvolutions\McpAdapter\Tests\Unit\Admin;

use WickedEvolutions\McpAdapter\Admin\PermissionManager;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class PermissionManagerTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		PermissionManager::clear_cache();
		// Reset the in-memory options store.
		$GLOBALS['wp_test_options'] = array();
	}

	// --- Permission derivation tests ---

	public function test_explicit_permission_read(): void {
		$ability = $this->make_ability( array( 'permission' => 'read' ) );
		$this->assertSame( 'read', PermissionManager::get_permission( $ability ) );
	}

	public function test_explicit_permission_write(): void {
		$ability = $this->make_ability( array( 'permission' => 'write' ) );
		$this->assertSame( 'write', PermissionManager::get_permission( $ability ) );
	}

	public function test_explicit_permission_delete(): void {
		$ability = $this->make_ability( array( 'permission' => 'delete' ) );
		$this->assertSame( 'delete', PermissionManager::get_permission( $ability ) );
	}

	public function test_explicit_permission_overrides_annotations(): void {
		$ability = $this->make_ability( array(
			'permission'  => 'write',
			'readonly'    => true,
			'destructive' => true,
		) );
		$this->assertSame( 'write', PermissionManager::get_permission( $ability ) );
	}

	public function test_readonly_derives_read(): void {
		$ability = $this->make_ability( array( 'readonly' => true ) );
		$this->assertSame( 'read', PermissionManager::get_permission( $ability ) );
	}

	public function test_destructive_derives_delete(): void {
		$ability = $this->make_ability( array( 'destructive' => true ) );
		$this->assertSame( 'delete', PermissionManager::get_permission( $ability ) );
	}

	public function test_not_readonly_not_destructive_derives_write(): void {
		$ability = $this->make_ability( array(
			'readonly'    => false,
			'destructive' => false,
		) );
		$this->assertSame( 'write', PermissionManager::get_permission( $ability ) );
	}

	public function test_readonly_false_destructive_false_derives_write(): void {
		$ability = $this->make_ability( array(
			'readonly'    => false,
			'destructive' => false,
			'idempotent'  => true,
		) );
		$this->assertSame( 'write', PermissionManager::get_permission( $ability ) );
	}

	public function test_no_annotations_defaults_to_read(): void {
		$ability = $this->make_ability( array() );
		$this->assertSame( 'read', PermissionManager::get_permission( $ability ) );
	}

	public function test_empty_meta_defaults_to_read(): void {
		$ability = new \WP_Ability( 'test/empty' );
		$this->assertSame( 'read', PermissionManager::get_permission( $ability ) );
	}

	public function test_invalid_explicit_permission_falls_through(): void {
		$ability = $this->make_ability( array( 'permission' => 'admin' ) );
		// 'admin' is not valid, so falls through to default.
		$this->assertSame( 'read', PermissionManager::get_permission( $ability ) );
	}

	// --- Enabled state tests ---

	public function test_default_enabled_when_no_settings(): void {
		$this->assertTrue( PermissionManager::is_enabled( 'test/ability' ) );
	}

	public function test_set_enabled_true(): void {
		PermissionManager::set_enabled( 'test/ability', true );
		$this->assertTrue( PermissionManager::is_enabled( 'test/ability' ) );
	}

	public function test_set_enabled_false(): void {
		PermissionManager::set_enabled( 'test/ability', false );
		$this->assertFalse( PermissionManager::is_enabled( 'test/ability' ) );
	}

	public function test_different_abilities_independent(): void {
		PermissionManager::set_enabled( 'test/one', true );
		PermissionManager::set_enabled( 'test/two', false );
		$this->assertTrue( PermissionManager::is_enabled( 'test/one' ) );
		$this->assertFalse( PermissionManager::is_enabled( 'test/two' ) );
	}

	// --- Validation tests ---

	public function test_valid_permissions(): void {
		$this->assertTrue( PermissionManager::is_valid_permission( 'read' ) );
		$this->assertTrue( PermissionManager::is_valid_permission( 'write' ) );
		$this->assertTrue( PermissionManager::is_valid_permission( 'delete' ) );
	}

	public function test_invalid_permissions(): void {
		$this->assertFalse( PermissionManager::is_valid_permission( '' ) );
		$this->assertFalse( PermissionManager::is_valid_permission( 'admin' ) );
		$this->assertFalse( PermissionManager::is_valid_permission( 'execute' ) );
	}

	// --- Constants tests ---

	public function test_option_name_constant(): void {
		$this->assertSame( 'mcp_adapter_ability_settings', PermissionManager::OPTION_NAME );
	}

	public function test_valid_permissions_array(): void {
		$this->assertSame( array( 'read', 'write', 'delete' ), PermissionManager::VALID_PERMISSIONS );
	}

	// --- Save settings tests ---

	public function test_save_settings_updates_cache(): void {
		$settings = array(
			'test/one' => array( 'enabled' => true ),
			'test/two' => array( 'enabled' => false ),
		);
		PermissionManager::save_settings( $settings );
		$this->assertTrue( PermissionManager::is_enabled( 'test/one' ) );
		$this->assertFalse( PermissionManager::is_enabled( 'test/two' ) );
	}

	public function test_clear_cache_reads_from_option_store(): void {
		// Set via option store directly to simulate persistent state.
		PermissionManager::set_enabled( 'test/cached', false );
		$this->assertFalse( PermissionManager::is_enabled( 'test/cached' ) );

		// Clear cache — forces re-read from get_option.
		PermissionManager::clear_cache();

		// The option store still has the value, so it should still be disabled.
		$this->assertFalse( PermissionManager::is_enabled( 'test/cached' ) );
	}

	public function test_clear_cache_with_empty_store_defaults_enabled(): void {
		// Clear options store entirely.
		$GLOBALS['wp_test_options'] = array();
		PermissionManager::clear_cache();

		// No settings → default enabled.
		$this->assertTrue( PermissionManager::is_enabled( 'test/nonexistent' ) );
	}

	// --- Helper ---

	private function make_ability( array $annotations ): \WP_Ability {
		return new \WP_Ability( 'test/ability', array(
			'meta' => array( 'annotations' => $annotations ),
		) );
	}
}
