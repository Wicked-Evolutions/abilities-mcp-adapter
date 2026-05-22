<?php
/**
 * #140 — error remediation on the mcp-adapter-execute-ability /
 * mcp-adapter-get-ability-info meta-tool permission path.
 *
 * The bug was a bypass: ToolsHandler rendered permission-callback WP_Errors
 * via McpErrorFactory::permission_denied() directly, so a name-resolution
 * failure surfaced from a permission_callback (ability_not_found) rendered as
 * -32008 "Permission denied: …" instead of -32003. The fix routes the
 * permission-phase WP_Error through McpErrorMapper::from_wp_error() with a
 * PERMISSION_DENIED default — exactly the call ToolsHandler now makes.
 *
 * These tests exercise the meta-tools' real permission_callback
 * (ExecuteAbilityAbility::check_permission / GetAbilityInfoAbility::check_permission)
 * and then apply that exact render so the three conditions are distinguished
 * end-to-end: not_found (-32003), not_exposed (-32008), genuine permission
 * denial (-32008).
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Handlers\Tools
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Handlers\Tools;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Abilities\ExecuteAbilityAbility;
use WickedEvolutions\McpAdapter\Abilities\GetAbilityInfoAbility;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthRequestContext;
use WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\McpErrorFactory;
use WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\McpErrorMapper;

final class PermissionErrorRemediationTest extends TestCase {

	protected function setUp(): void {
		OAuthRequestContext::reset();
		$GLOBALS['wp_test_abilities']    = array();
		$GLOBALS['wp_test_current_user'] = 7;
		$GLOBALS['wp_test_caps']         = array( 'read' => true );
	}

	protected function tearDown(): void {
		OAuthRequestContext::reset();
		$GLOBALS['wp_test_abilities'] = array();
		unset( $GLOBALS['wp_test_current_user'], $GLOBALS['wp_test_caps'] );
	}

	/**
	 * Mirror of the ToolsHandler permission-failure render after the #140 fix:
	 * a permission-phase WP_Error is routed through the mapper with a
	 * PERMISSION_DENIED default.
	 */
	private function render_permission_failure( \WP_Error $wp_error ): array {
		return McpErrorMapper::from_wp_error( 1, $wp_error, McpErrorFactory::PERMISSION_DENIED )['error'];
	}

	private function register_ability( string $name, array $meta ): void {
		$GLOBALS['wp_test_abilities'][ $name ] = new \WP_Ability( $name, array( 'meta' => $meta ) );
	}

	// ── Condition 1: not-found ────────────────────────────────────────────

	public function test_execute_ability_bad_name_renders_not_found_not_permission_denied(): void {
		// content/list-posts is not registered — the trait exposure check fires first.
		$err = ExecuteAbilityAbility::check_permission( array( 'ability_name' => 'content/list-posts' ) );
		$this->assertInstanceOf( \WP_Error::class, $err );
		$this->assertSame( 'ability_not_found', $err->get_error_code() );

		$rendered = $this->render_permission_failure( $err );

		$this->assertSame( McpErrorFactory::TOOL_NOT_FOUND, $rendered['code'], 'bad name → -32003, not -32008' );
		$this->assertSame( "Ability 'content/list-posts' not found", $rendered['message'] );
		$this->assertStringNotContainsStringIgnoringCase( 'Permission denied', $rendered['message'] );
		$this->assertSame( 'not_found', $rendered['data']['reason'] );
		$this->assertStringContainsString( 'discover-abilities', $rendered['data']['hint'] );
	}

	public function test_get_ability_info_bad_name_renders_not_found(): void {
		$err = GetAbilityInfoAbility::check_permission( array( 'ability_name' => 'content/list-posts' ) );
		$this->assertInstanceOf( \WP_Error::class, $err );
		$this->assertSame( 'ability_not_found', $err->get_error_code() );

		$rendered = $this->render_permission_failure( $err );

		$this->assertSame( McpErrorFactory::TOOL_NOT_FOUND, $rendered['code'] );
		$this->assertSame( 'not_found', $rendered['data']['reason'] );
		$this->assertStringContainsString( 'discover-abilities', $rendered['data']['hint'] );
		$this->assertStringNotContainsStringIgnoringCase( 'Permission denied', $rendered['message'] );
	}

	// ── Condition 2: not-exposed-via-MCP ──────────────────────────────────

	public function test_exists_but_not_public_renders_not_exposed_permission_denied(): void {
		// Registered, but no mcp.public / show_in_rest → exists but not exposed.
		$this->register_ability( 'content/list-posts', array( 'mcp' => array( 'public' => false ) ) );

		$err = ExecuteAbilityAbility::check_permission( array( 'ability_name' => 'content/list-posts' ) );
		$this->assertInstanceOf( \WP_Error::class, $err );
		$this->assertSame( 'ability_not_public_mcp', $err->get_error_code() );

		$rendered = $this->render_permission_failure( $err );

		$this->assertSame( McpErrorFactory::PERMISSION_DENIED, $rendered['code'], 'not-exposed → -32008' );
		$this->assertSame( 'not_exposed', $rendered['data']['reason'] );
		// Distinct from not-found: this is NOT -32003.
		$this->assertNotSame( McpErrorFactory::TOOL_NOT_FOUND, $rendered['code'] );
	}

	// ── Condition 3: genuine permission denial keeps -32008 ───────────────

	public function test_genuine_permission_denial_keeps_permission_denied(): void {
		// A public ability whose own permission_callback denies — a real auth
		// failure, distinct from name resolution.
		$ability = new class( 'content/list-posts', array(
			'meta' => array( 'mcp' => array( 'public' => true ) ),
		) ) extends \WP_Ability {
			public function check_permissions( $args = null ) {
				return new \WP_Error( 'ability_invalid_permissions', 'You are not allowed to do this.' );
			}
		};
		$GLOBALS['wp_test_abilities']['content/list-posts'] = $ability;

		$err = ExecuteAbilityAbility::check_permission( array( 'ability_name' => 'content/list-posts' ) );
		$this->assertInstanceOf( \WP_Error::class, $err );
		$this->assertSame( 'ability_invalid_permissions', $err->get_error_code() );

		$rendered = $this->render_permission_failure( $err );
		$this->assertSame( McpErrorFactory::PERMISSION_DENIED, $rendered['code'] );
	}

	// ── Condition 4: scope-denied reason at the inner underlying gate ──────

	public function test_inner_scope_denial_carries_insufficient_scope_reason(): void {
		$inner = new class( 'users/create', array(
			'category' => 'users',
			'meta'     => array(
				'annotations' => array( 'permission' => 'write' ),
				'mcp'         => array( 'public' => true ),
			),
		) ) extends \WP_Ability {
			public function check_permissions( $args = null ) { return true; }
			public function get_input_schema() { return array(); }
			public function execute( $args = null ) { return array( 'created' => true ); }
		};
		$GLOBALS['wp_test_abilities']['users/create'] = $inner;

		// Token has the outer scope but not the inner sensitive write scope.
		OAuthRequestContext::set(
			7,
			array( 'abilities:mcp-adapter:read' ),
			'https://example.com/wp-json/mcp/abilities-mcp-adapter-default-server',
			'cl_test',
			1
		);

		$result = ExecuteAbilityAbility::execute( array(
			'ability_name' => 'users/create',
			'parameters'   => array(),
		) );

		$this->assertFalse( $result['success'] );
		$this->assertSame( 'insufficient_scope', $result['error_code'] );
		$this->assertSame( 'abilities:users:write', $result['required_scope'] );
		$this->assertSame( 'insufficient_scope', $result['reason'], 'inner gate carries data.reason' );
	}
}
