<?php
/**
 * #88: SelectedRoleEnforcer — caps downgrade for OAuth-bound user.
 *
 * Pins the contract for the `user_has_cap` filter that scopes a multi-role
 * operator's effective capabilities to the role they selected at consent.
 *
 * Pass-through paths (must not mutate $allcaps):
 *   - Not an OAuth request
 *   - selected_role is empty (single-role op or auto-approve path — the
 *     latter is the deliberate v1.4.5 carve-out tracked as a known limitation
 *     and follow-up issue #94)
 *   - User being checked is not the OAuth-bound user (defensive — no
 *     downgrade for other users on the same request)
 *
 * Downgrade path:
 *   - $allcaps replaced wholesale with the selected role's capability map
 *
 * Fail-closed:
 *   - Unknown role slug → empty caps (never silently full caps)
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthRequestContext;
use WickedEvolutions\McpAdapter\Auth\OAuth\SelectedRoleEnforcer;

final class SelectedRoleEnforcerTest extends TestCase {

	protected function setUp(): void {
		OAuthRequestContext::reset();
		SelectedRoleEnforcer::set_resolver( null );
		$GLOBALS['wp_test_roles'] = array(
			'administrator' => array(
				'name'         => 'Administrator',
				'capabilities' => array(
					'manage_options' => true,
					'edit_posts'     => true,
					'edit_pages'     => true,
				),
			),
			'editor' => array(
				'name'         => 'Editor',
				'capabilities' => array(
					'edit_posts' => true,
					'edit_pages' => true,
				),
			),
			'author' => array(
				'name'         => 'Author',
				'capabilities' => array(
					'edit_posts' => true,
				),
			),
		);
	}

	protected function tearDown(): void {
		OAuthRequestContext::reset();
		SelectedRoleEnforcer::set_resolver( null );
		unset( $GLOBALS['wp_test_roles'] );
	}

	// -------------------------------------------------------------------------
	// Pass-through paths
	// -------------------------------------------------------------------------

	public function test_passthrough_when_not_an_oauth_request(): void {
		$allcaps = array( 'manage_options' => true, 'edit_posts' => true );
		$user    = (object) array( 'ID' => 7 );

		$result = SelectedRoleEnforcer::apply( $allcaps, array( 'manage_options' ), array(), $user );

		$this->assertSame( $allcaps, $result, 'Non-OAuth requests must pass through untouched.' );
	}

	public function test_passthrough_when_selected_role_is_empty(): void {
		// OAuth request, but selected_role is '' — single-role op, or auto-approve.
		OAuthRequestContext::set( 7, array( 'abilities:read' ), 'https://example.com/wp-json/mcp/x', 'client-x', 1, '' );

		$allcaps = array( 'manage_options' => true );
		$user    = (object) array( 'ID' => 7 );

		$result = SelectedRoleEnforcer::apply( $allcaps, array( 'manage_options' ), array(), $user );

		$this->assertSame( $allcaps, $result, 'Empty selected_role must not downgrade.' );
	}

	public function test_passthrough_when_checked_user_is_not_oauth_bound_user(): void {
		// OAuth bound to user 7; cap check is against user 42 (e.g. admin UI
		// inspecting another user's caps). We must not downgrade user 42.
		OAuthRequestContext::set( 7, array(), 'https://example.com/wp-json/mcp/x', 'client-x', 1, 'editor' );

		$allcaps = array( 'manage_options' => true, 'edit_posts' => true );
		$user    = (object) array( 'ID' => 42 );

		$result = SelectedRoleEnforcer::apply( $allcaps, array( 'manage_options' ), array(), $user );

		$this->assertSame( $allcaps, $result );
	}

	public function test_passthrough_when_user_id_unresolvable(): void {
		// Edge: filter called with a $user that has no ID property and isn't numeric.
		OAuthRequestContext::set( 7, array(), 'https://example.com/wp-json/mcp/x', 'client-x', 1, 'editor' );

		$allcaps = array( 'manage_options' => true );
		$result  = SelectedRoleEnforcer::apply( $allcaps, array( 'manage_options' ), array(), null );

		$this->assertSame( $allcaps, $result );
	}

	// -------------------------------------------------------------------------
	// Downgrade path
	// -------------------------------------------------------------------------

	public function test_downgrades_oauth_bound_user_caps_to_selected_role(): void {
		OAuthRequestContext::set( 7, array(), 'https://example.com/wp-json/mcp/x', 'client-x', 1, 'editor' );

		$allcaps = array( 'manage_options' => true, 'edit_posts' => true, 'edit_pages' => true );
		$user    = (object) array( 'ID' => 7 );

		$result = SelectedRoleEnforcer::apply( $allcaps, array( 'manage_options' ), array(), $user );

		// Editor caps replace $allcaps entirely — manage_options is gone.
		$this->assertArrayNotHasKey( 'manage_options', $result, 'Admin-only cap must not survive editor downgrade.' );
		$this->assertSame( true, $result['edit_posts'] ?? null );
		$this->assertSame( true, $result['edit_pages'] ?? null );
	}

	public function test_downgrade_is_deterministic_across_repeated_calls(): void {
		OAuthRequestContext::set( 7, array(), 'https://example.com/wp-json/mcp/x', 'client-x', 1, 'author' );

		$allcaps = array( 'manage_options' => true, 'edit_posts' => true );
		$user    = (object) array( 'ID' => 7 );

		$first  = SelectedRoleEnforcer::apply( $allcaps, array( 'edit_posts' ), array(), $user );
		$second = SelectedRoleEnforcer::apply( $allcaps, array( 'edit_posts' ), array(), $user );

		$this->assertSame( $first, $second );
		$this->assertArrayNotHasKey( 'manage_options', $first );
	}

	public function test_downgrade_resolves_user_id_from_numeric_argument(): void {
		// Some callers pass a user ID rather than a WP_User object.
		OAuthRequestContext::set( 7, array(), 'https://example.com/wp-json/mcp/x', 'client-x', 1, 'editor' );

		$allcaps = array( 'manage_options' => true, 'edit_posts' => true );

		$result = SelectedRoleEnforcer::apply( $allcaps, array( 'manage_options' ), array(), 7 );

		$this->assertArrayNotHasKey( 'manage_options', $result );
		$this->assertSame( true, $result['edit_posts'] ?? null );
	}

	// -------------------------------------------------------------------------
	// Fail-closed: unknown role
	// -------------------------------------------------------------------------

	public function test_unknown_role_yields_empty_caps_not_full_caps(): void {
		// If a token somehow carried a role slug that no longer exists (role
		// removed by an admin between consent and bearer-auth), the enforcer
		// must fail closed — zero caps, not the user's underlying allcaps.
		OAuthRequestContext::set( 7, array(), 'https://example.com/wp-json/mcp/x', 'client-x', 1, 'phantom_role' );

		$allcaps = array( 'manage_options' => true, 'edit_posts' => true );
		$user    = (object) array( 'ID' => 7 );

		$result = SelectedRoleEnforcer::apply( $allcaps, array( 'manage_options' ), array(), $user );

		$this->assertSame( array(), $result );
	}

	public function test_role_with_empty_capabilities_yields_empty_caps(): void {
		$GLOBALS['wp_test_roles']['empty_role'] = array(
			'name'         => 'Empty',
			'capabilities' => array(),
		);
		OAuthRequestContext::set( 7, array(), 'https://example.com/wp-json/mcp/x', 'client-x', 1, 'empty_role' );

		$allcaps = array( 'manage_options' => true );
		$user    = (object) array( 'ID' => 7 );

		$result = SelectedRoleEnforcer::apply( $allcaps, array( 'manage_options' ), array(), $user );

		$this->assertSame( array(), $result );
	}

	// -------------------------------------------------------------------------
	// Resolver injection (tests / future overrides)
	// -------------------------------------------------------------------------

	public function test_custom_resolver_overrides_wp_roles_default(): void {
		SelectedRoleEnforcer::set_resolver( static function ( string $role ): array {
			return $role === 'custom' ? array( 'custom_cap' => true ) : array();
		} );

		OAuthRequestContext::set( 7, array(), 'https://example.com/wp-json/mcp/x', 'client-x', 1, 'custom' );

		$allcaps = array( 'manage_options' => true );
		$user    = (object) array( 'ID' => 7 );

		$result = SelectedRoleEnforcer::apply( $allcaps, array( 'custom_cap' ), array(), $user );

		$this->assertSame( array( 'custom_cap' => true ), $result );
	}

	public function test_resolver_returning_non_array_falls_back_to_empty(): void {
		SelectedRoleEnforcer::set_resolver( static function ( string $role ) {
			return null;
		} );

		OAuthRequestContext::set( 7, array(), 'https://example.com/wp-json/mcp/x', 'client-x', 1, 'editor' );

		$allcaps = array( 'manage_options' => true );
		$user    = (object) array( 'ID' => 7 );

		$result = SelectedRoleEnforcer::apply( $allcaps, array( 'manage_options' ), array(), $user );

		$this->assertSame( array(), $result );
	}

	// -------------------------------------------------------------------------
	// role_capabilities() direct contract (used by future callers + diagnostics)
	// -------------------------------------------------------------------------

	public function test_role_capabilities_returns_role_caps_for_known_slug(): void {
		$caps = SelectedRoleEnforcer::role_capabilities( 'editor' );

		$this->assertSame( true, $caps['edit_posts'] ?? null );
		$this->assertArrayNotHasKey( 'manage_options', $caps );
	}

	public function test_role_capabilities_empty_string_returns_empty_array(): void {
		$this->assertSame( array(), SelectedRoleEnforcer::role_capabilities( '' ) );
	}

	public function test_role_capabilities_unknown_role_returns_empty_array(): void {
		$this->assertSame( array(), SelectedRoleEnforcer::role_capabilities( 'phantom_role' ) );
	}
}
