<?php
/**
 * Tests for RoleSelector — implements the Appendix H.4.5 server-side
 * role-escalation guard.
 *
 * Even if the consent form is tampered to include a role the operator does
 * not hold, the POST handler must reject it. RoleSelector is the central
 * arbiter of "is this role even available to this user?".
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\RoleSelector;

final class RoleSelectorTest extends TestCase {

	public function test_returns_roles_from_resolver(): void {
		$roles = RoleSelector::roles_for_user_id( 42, fn() => array( 'editor', 'author' ) );
		$this->assertSame( array( 'editor', 'author' ), $roles );
	}

	public function test_drops_non_string_role_values_from_resolver(): void {
		$roles = RoleSelector::roles_for_user_id( 42, fn() => array( 'editor', 99, null, 'author' ) );
		$this->assertSame( array( 'editor', 'author' ), $roles );
	}

	public function test_returns_empty_array_when_resolver_returns_non_array(): void {
		$roles = RoleSelector::roles_for_user_id( 42, fn() => null );
		$this->assertSame( array(), $roles );
	}

	public function test_user_holds_role_returns_true_for_role_in_user_set(): void {
		$this->assertTrue( RoleSelector::user_holds_role( 42, 'editor', fn() => array( 'editor', 'author' ) ) );
	}

	public function test_user_holds_role_returns_false_for_role_not_in_user_set(): void {
		// This is the H.4.5 escalation prevention contract.
		$this->assertFalse( RoleSelector::user_holds_role( 42, 'administrator', fn() => array( 'editor' ) ) );
	}

	public function test_user_holds_role_returns_false_for_empty_submitted_role(): void {
		$this->assertFalse( RoleSelector::user_holds_role( 42, '', fn() => array( 'editor' ) ) );
	}

	public function test_user_holds_role_falls_through_to_get_userdata_when_no_resolver(): void {
		$GLOBALS['wp_test_users'] = array(
			7 => array( 'user_login' => 'owen', 'roles' => array( 'shop_manager', 'subscriber' ) ),
		);
		$this->assertTrue(  RoleSelector::user_holds_role( 7, 'shop_manager' ) );
		$this->assertFalse( RoleSelector::user_holds_role( 7, 'administrator' ) );
	}

	public function test_user_holds_role_returns_false_when_user_does_not_exist(): void {
		$GLOBALS['wp_test_users'] = array();
		$this->assertFalse( RoleSelector::user_holds_role( 999, 'editor' ) );
	}
}
