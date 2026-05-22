<?php
/**
 * #139 — discover-abilities lean defaults: compact-by-default, default page
 * size, always-present pagination envelope + categories histogram, and
 * backward-compatible verbose opt-out.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Abilities
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Abilities;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Abilities\DiscoverAbilitiesAbility;

final class DiscoverAbilitiesDefaultsTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_abilities']    = array();
		$GLOBALS['wp_test_current_user'] = 7;
		$GLOBALS['wp_test_caps']         = array( 'read' => true );
	}

	protected function tearDown(): void {
		$GLOBALS['wp_test_abilities'] = array();
		unset( $GLOBALS['wp_test_current_user'], $GLOBALS['wp_test_caps'] );
	}

	private function register( string $name, string $category ): void {
		$GLOBALS['wp_test_abilities'][ $name ] = new \WP_Ability(
			$name,
			array(
				'category'    => $category,
				'label'       => $name,
				'description' => "description of {$name}",
				'meta'        => array( 'mcp' => array( 'public' => true ) ),
			)
		);
	}

	private function register_many( string $category, int $count, string $prefix ): void {
		for ( $i = 1; $i <= $count; $i++ ) {
			$this->register( "{$prefix}/item-{$i}", $category );
		}
	}

	// ── No-args lean default ──────────────────────────────────────────────

	public function test_no_args_defaults_to_compact_and_limit_100(): void {
		$this->register_many( 'content', 150, 'content' );

		$res = DiscoverAbilitiesAbility::execute( array() );

		// Compact entries: name/category/tier only, no label/description.
		$this->assertCount( 100, $res['abilities'], 'default page size is 100' );
		$first = $res['abilities'][0];
		$this->assertArrayHasKey( 'name', $first );
		$this->assertArrayHasKey( 'category', $first );
		$this->assertArrayHasKey( 'tier', $first );
		$this->assertArrayNotHasKey( 'label', $first );
		$this->assertArrayNotHasKey( 'description', $first );

		// Pagination envelope (always present, self-documenting).
		$this->assertSame(
			array(
				'total'          => 150,
				'filtered_total' => 150,
				'returned'       => 100,
				'offset'         => 0,
				'next_offset'    => 100,
				'has_more'       => true,
				'compact'        => true,
			),
			$res['pagination']
		);

		// Histogram present.
		$this->assertSame( array( array( 'slug' => 'content', 'count' => 150 ) ), $res['categories'] );

		// The old underscore-prefixed key is gone.
		$this->assertArrayNotHasKey( '_pagination', $res );
	}

	public function test_second_page_has_no_more(): void {
		$this->register_many( 'content', 150, 'content' );

		$res = DiscoverAbilitiesAbility::execute( array( 'offset' => 100 ) );

		$this->assertCount( 50, $res['abilities'] );
		$this->assertSame( 100, $res['pagination']['offset'] );
		$this->assertSame( 50, $res['pagination']['returned'] );
		$this->assertFalse( $res['pagination']['has_more'] );
		$this->assertNull( $res['pagination']['next_offset'] );
	}

	// ── Verbose opt-out (backward compat) ─────────────────────────────────

	public function test_explicit_verbose_unbounded_returns_prior_shape_plus_additive_blocks(): void {
		$this->register_many( 'content', 150, 'content' );

		$res = DiscoverAbilitiesAbility::execute( array( 'compact' => false, 'limit' => 0 ) );

		// Prior verbose shape: all entries, with label + description.
		$this->assertCount( 150, $res['abilities'], 'compact:false + limit:0 is unbounded' );
		$first = $res['abilities'][0];
		$this->assertArrayHasKey( 'label', $first );
		$this->assertArrayHasKey( 'description', $first );

		// Prior top-level keys preserved.
		$this->assertSame( 150, $res['total'] );
		$this->assertFalse( $res['filtered'] );

		// Additive blocks present and self-consistent.
		$this->assertFalse( $res['pagination']['compact'] );
		$this->assertSame( 150, $res['pagination']['returned'] );
		$this->assertFalse( $res['pagination']['has_more'] );
		$this->assertNull( $res['pagination']['next_offset'] );
		$this->assertNotEmpty( $res['categories'] );
	}

	public function test_explicit_compact_false_without_limit_does_not_auto_apply_limit(): void {
		$this->register_many( 'content', 150, 'content' );

		// Explicit compact:false suppresses the auto-limit even with no limit arg.
		$res = DiscoverAbilitiesAbility::execute( array( 'compact' => false ) );

		$this->assertCount( 150, $res['abilities'], 'explicit compact:false → unbounded' );
		$this->assertFalse( $res['pagination']['compact'] );
		$this->assertFalse( $res['pagination']['has_more'] );
	}

	// ── Category filter ───────────────────────────────────────────────────

	public function test_category_filter_sets_filtered_total_and_single_slug_histogram(): void {
		$this->register_many( 'fluent-crm', 30, 'fluent-crm' );
		$this->register_many( 'content', 20, 'content' );
		$this->register_many( 'media', 10, 'media' );

		$res = DiscoverAbilitiesAbility::execute( array( 'category' => 'fluent-crm' ) );

		// Compact by default, filtered to fluent-crm.
		$this->assertTrue( $res['pagination']['compact'] );
		$this->assertSame( 60, $res['pagination']['total'], 'unfiltered total spans all categories' );
		$this->assertSame( 30, $res['pagination']['filtered_total'], 'filtered_total is the category count' );
		$this->assertTrue( $res['filtered'] );

		foreach ( $res['abilities'] as $entry ) {
			$this->assertSame( 'fluent-crm', $entry['category'] );
		}

		// Histogram contains only the filtered category.
		$this->assertSame( array( array( 'slug' => 'fluent-crm', 'count' => 30 ) ), $res['categories'] );
	}

	public function test_histogram_counts_are_accurate_and_sorted_by_count_desc(): void {
		$this->register_many( 'fluent-crm', 30, 'fluent-crm' );
		$this->register_many( 'content', 20, 'content' );
		$this->register_many( 'media', 10, 'media' );

		$res = DiscoverAbilitiesAbility::execute( array() );

		$this->assertSame(
			array(
				array( 'slug' => 'fluent-crm', 'count' => 30 ),
				array( 'slug' => 'content', 'count' => 20 ),
				array( 'slug' => 'media', 'count' => 10 ),
			),
			$res['categories']
		);
	}

	// ── Exposure gates still honored ──────────────────────────────────────

	public function test_non_public_and_non_tool_abilities_excluded_from_totals(): void {
		$this->register( 'content/list', 'content' );
		// Not public — must not count.
		$GLOBALS['wp_test_abilities']['secret/thing'] = new \WP_Ability(
			'secret/thing',
			array( 'category' => 'secret', 'meta' => array( 'mcp' => array( 'public' => false ) ) )
		);
		// Public but not type=tool — must not count.
		$GLOBALS['wp_test_abilities']['content/feed'] = new \WP_Ability(
			'content/feed',
			array( 'category' => 'content', 'meta' => array( 'mcp' => array( 'public' => true, 'type' => 'resource' ) ) )
		);

		$res = DiscoverAbilitiesAbility::execute( array() );

		$this->assertSame( 1, $res['pagination']['total'] );
		$this->assertSame( 1, $res['pagination']['filtered_total'] );
		$this->assertSame( array( array( 'slug' => 'content', 'count' => 1 ) ), $res['categories'] );
	}
}
