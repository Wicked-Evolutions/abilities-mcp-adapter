<?php

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Domain\Utils;

use WickedEvolutions\McpAdapter\Domain\Utils\McpAnnotationMapper;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class McpAnnotationMapperTest extends TestCase {

	// ── map() with tool feature ──

	public function test_map_readonly_annotation_for_tool(): void {
		$annotations = array( 'readonly' => true );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertTrue( $result['readOnlyHint'] );
	}

	public function test_map_destructive_annotation_for_tool(): void {
		$annotations = array( 'destructive' => true );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertTrue( $result['destructiveHint'] );
	}

	public function test_map_idempotent_annotation_for_tool(): void {
		$annotations = array( 'idempotent' => false );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertFalse( $result['idempotentHint'] );
	}

	public function test_map_category_for_tool(): void {
		$annotations = array( 'category' => 'content' );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertSame( 'content', $result['category'] );
	}

	public function test_map_tier_for_tool(): void {
		$annotations = array( 'tier' => 'pro' );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertSame( 'pro', $result['tier'] );
	}

	public function test_map_bridge_hints_for_tool(): void {
		$annotations = array( 'bridge_hints' => array( 'timeout' => 30 ) );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertSame( array( 'timeout' => 30 ), $result['bridgeHints'] );
	}

	public function test_map_shared_annotations_for_tool(): void {
		$annotations = array(
			'audience'     => array( 'user' ),
			'lastModified' => '2026-03-08T00:00:00Z',
			'priority'     => 0.8,
		);
		$result = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertSame( array( 'user' ), $result['audience'] );
		$this->assertSame( '2026-03-08T00:00:00Z', $result['lastModified'] );
		$this->assertSame( 0.8, $result['priority'] );
	}

	public function test_map_open_world_hint_for_tool(): void {
		$annotations = array( 'openWorldHint' => true );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertTrue( $result['openWorldHint'] );
	}

	public function test_map_title_for_tool(): void {
		$annotations = array( 'title' => 'My Tool Title' );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertSame( 'My Tool Title', $result['title'] );
	}

	// ── Feature filtering ──

	public function test_map_excludes_tool_only_annotations_for_resource(): void {
		$annotations = array(
			'readonly'    => true,
			'destructive' => false,
			'idempotent'  => true,
			'category'    => 'content',
		);
		$result = McpAnnotationMapper::map( $annotations, 'resource' );

		$this->assertArrayNotHasKey( 'readOnlyHint', $result );
		$this->assertArrayNotHasKey( 'destructiveHint', $result );
		$this->assertArrayNotHasKey( 'idempotentHint', $result );
		$this->assertSame( 'content', $result['category'] );
	}

	public function test_map_excludes_tool_only_annotations_for_prompt(): void {
		$annotations = array(
			'readonly'       => true,
			'openWorldHint'  => true,
			'title'          => 'A title',
			'audience'       => array( 'assistant' ),
		);
		$result = McpAnnotationMapper::map( $annotations, 'prompt' );

		$this->assertArrayNotHasKey( 'readOnlyHint', $result );
		$this->assertArrayNotHasKey( 'openWorldHint', $result );
		$this->assertArrayNotHasKey( 'title', $result );
		$this->assertSame( array( 'assistant' ), $result['audience'] );
	}

	public function test_map_shared_annotations_available_for_resource(): void {
		$annotations = array(
			'audience'     => array( 'user', 'assistant' ),
			'lastModified' => '2026-01-01T00:00:00Z',
			'priority'     => 0.5,
			'category'     => 'files',
			'tier'         => 'free',
			'bridge_hints' => array( 'cache' => true ),
		);
		$result = McpAnnotationMapper::map( $annotations, 'resource' );

		$this->assertArrayHasKey( 'audience', $result );
		$this->assertArrayHasKey( 'lastModified', $result );
		$this->assertArrayHasKey( 'priority', $result );
		$this->assertArrayHasKey( 'category', $result );
		$this->assertArrayHasKey( 'tier', $result );
		$this->assertArrayHasKey( 'bridgeHints', $result );
	}

	// ── Unknown annotations ──

	public function test_map_ignores_unknown_annotations(): void {
		$annotations = array(
			'unknownField'  => 'value',
			'anotherCustom' => 123,
		);
		$result = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertEmpty( $result );
	}

	// ── Type casting ──

	public function test_map_casts_boolean_from_truthy(): void {
		$annotations = array( 'readonly' => 1 );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertTrue( $result['readOnlyHint'] );
	}

	public function test_map_casts_string_trims_whitespace(): void {
		$annotations = array( 'category' => '  content  ' );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertSame( 'content', $result['category'] );
	}

	public function test_map_string_empty_after_trim_excluded(): void {
		$annotations = array( 'category' => '   ' );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertArrayNotHasKey( 'category', $result );
	}

	public function test_map_array_empty_excluded(): void {
		$annotations = array( 'audience' => array() );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertArrayNotHasKey( 'audience', $result );
	}

	public function test_map_number_cast_to_float(): void {
		$annotations = array( 'priority' => '0.7' );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertSame( 0.7, $result['priority'] );
	}

	public function test_map_number_non_numeric_excluded(): void {
		$annotations = array( 'priority' => 'high' );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertArrayNotHasKey( 'priority', $result );
	}

	// ── Null values ──

	public function test_map_null_values_excluded(): void {
		$annotations = array(
			'readonly'  => null,
			'category'  => null,
			'audience'  => null,
			'priority'  => null,
		);
		$result = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertEmpty( $result );
	}

	// ── WordPress property name takes precedence ──

	public function test_map_ability_property_overrides_mcp_field(): void {
		// Both 'readonly' (ability_property) and 'readOnlyHint' (mcp_field) present.
		// ability_property should win.
		$annotations = array(
			'readonly'     => true,
			'readOnlyHint' => false,
		);
		$result = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertTrue( $result['readOnlyHint'] );
	}

	public function test_map_falls_back_to_mcp_field_name(): void {
		$annotations = array( 'readOnlyHint' => true );
		$result      = McpAnnotationMapper::map( $annotations, 'tool' );

		$this->assertTrue( $result['readOnlyHint'] );
	}
}
