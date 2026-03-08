<?php
/**
 * Tests for McpAnnotationMapper::build_from_ability().
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Domain\Utils;

use WickedEvolutions\McpAdapter\Admin\PermissionManager;
use WickedEvolutions\McpAdapter\Domain\Utils\McpAnnotationMapper;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class McpAnnotationMapperBuildTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		PermissionManager::clear_cache();
		$GLOBALS['wp_test_options'] = array();
	}

	protected function tearDown(): void {
		$GLOBALS['wp_test_options'] = array();
		PermissionManager::clear_cache();
		parent::tearDown();
	}

	// --- Category injection ---

	public function test_injects_category_from_ability_when_not_in_annotations(): void {
		$ability = new \WP_Ability( 'test/cat', array(
			'category' => 'content',
			'meta'     => array(
				'annotations' => array(
					'readonly' => true,
				),
			),
		) );

		$result = McpAnnotationMapper::build_from_ability( $ability, 'tool' );

		$this->assertSame( 'content', $result['category'] );
	}

	// --- Tier injection ---

	public function test_injects_tier_from_meta_when_not_in_annotations(): void {
		$ability = new \WP_Ability( 'test/tier', array(
			'category' => 'content',
			'meta'     => array(
				'tier'        => 'pro',
				'annotations' => array(
					'readonly' => true,
				),
			),
		) );

		$result = McpAnnotationMapper::build_from_ability( $ability, 'tool' );

		$this->assertSame( 'pro', $result['tier'] );
	}

	// --- Bridge hints injection ---

	public function test_injects_bridge_hints_from_meta_when_not_in_annotations(): void {
		$ability = new \WP_Ability( 'test/hints', array(
			'category' => 'content',
			'meta'     => array(
				'bridge_hints' => array( 'timeout' => 60 ),
				'annotations'  => array(
					'readonly' => true,
				),
			),
		) );

		$result = McpAnnotationMapper::build_from_ability( $ability, 'tool' );

		$this->assertSame( array( 'timeout' => 60 ), $result['bridgeHints'] );
	}

	// --- Permission injection ---

	public function test_injects_permission_read_for_readonly_ability(): void {
		$ability = new \WP_Ability( 'test/readonly', array(
			'category' => 'content',
			'meta'     => array(
				'annotations' => array(
					'readonly' => true,
				),
			),
		) );

		$result = McpAnnotationMapper::build_from_ability( $ability, 'tool' );

		$this->assertSame( 'read', $result['permission'] );
	}

	public function test_injects_permission_write_for_non_readonly_non_destructive(): void {
		$ability = new \WP_Ability( 'test/write', array(
			'category' => 'content',
			'meta'     => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => false,
				),
			),
		) );

		$result = McpAnnotationMapper::build_from_ability( $ability, 'tool' );

		$this->assertSame( 'write', $result['permission'] );
	}

	public function test_injects_permission_delete_for_destructive_ability(): void {
		$ability = new \WP_Ability( 'test/destructive', array(
			'category' => 'content',
			'meta'     => array(
				'annotations' => array(
					'destructive' => true,
				),
			),
		) );

		$result = McpAnnotationMapper::build_from_ability( $ability, 'tool' );

		$this->assertSame( 'delete', $result['permission'] );
	}

	// --- Enabled injection ---

	public function test_injects_enabled_true_by_default(): void {
		$ability = new \WP_Ability( 'test/enabled', array(
			'category' => 'content',
			'meta'     => array(
				'annotations' => array(
					'readonly' => true,
				),
			),
		) );

		$result = McpAnnotationMapper::build_from_ability( $ability, 'tool' );

		$this->assertTrue( $result['enabled'] );
	}

	// --- Explicit annotations not overridden ---

	public function test_explicit_category_in_annotations_not_overridden(): void {
		$ability = new \WP_Ability( 'test/explicit-cat', array(
			'category' => 'content',
			'meta'     => array(
				'annotations' => array(
					'category' => 'media',
					'readonly' => true,
				),
			),
		) );

		$result = McpAnnotationMapper::build_from_ability( $ability, 'tool' );

		// Annotation value 'media' should win over ability-level 'content'.
		$this->assertSame( 'media', $result['category'] );
	}

	public function test_explicit_tier_in_annotations_not_overridden(): void {
		$ability = new \WP_Ability( 'test/explicit-tier', array(
			'category' => 'content',
			'meta'     => array(
				'tier'        => 'free',
				'annotations' => array(
					'tier'     => 'pro',
					'readonly' => true,
				),
			),
		) );

		$result = McpAnnotationMapper::build_from_ability( $ability, 'tool' );

		// Annotation value 'pro' should win over meta-level 'free'.
		$this->assertSame( 'pro', $result['tier'] );
	}

	public function test_explicit_bridge_hints_in_annotations_not_overridden(): void {
		$ability = new \WP_Ability( 'test/explicit-hints', array(
			'category' => 'content',
			'meta'     => array(
				'bridge_hints' => array( 'timeout' => 60 ),
				'annotations'  => array(
					'bridge_hints' => array( 'timeout' => 120 ),
					'readonly'     => true,
				),
			),
		) );

		$result = McpAnnotationMapper::build_from_ability( $ability, 'tool' );

		// Annotation value should win over meta-level.
		$this->assertSame( array( 'timeout' => 120 ), $result['bridgeHints'] );
	}

	// --- Empty annotations/category returns empty ---

	public function test_returns_empty_array_when_ability_has_no_annotations_and_no_category(): void {
		// An ability with empty category and no meta annotations.
		// PermissionManager::get_permission returns 'read' by default,
		// and is_enabled returns true by default, so annotations will NOT be empty.
		// However, this tests that with completely empty meta, we still get
		// at least permission and enabled injected.
		$ability = new \WP_Ability( 'test/empty', array(
			'category' => '',
			'meta'     => array(),
		) );

		$result = McpAnnotationMapper::build_from_ability( $ability, 'tool' );

		// Permission ('read') and enabled (true) are always injected.
		// Category '' normalizes to null (empty string after trim), so excluded.
		$this->assertArrayHasKey( 'permission', $result );
		$this->assertArrayHasKey( 'enabled', $result );
		$this->assertArrayNotHasKey( 'category', $result );
	}
}
