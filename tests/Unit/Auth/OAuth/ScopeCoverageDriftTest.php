<?php
/**
 * Coverage-test side of Principle 9 — Scope Coverage Is Derived Or Coverage-Tested.
 *
 * The OAuth scope enforcer derives `abilities:<category>:<op>` from each
 * ability's category at execute time. If the registry surfaces a category
 * that {@see ScopeRegistry::all_scopes()} does not declare, the bridge
 * cannot request the scope and a full-catalog OAuth grant fails to cover
 * the affected ability — that's exactly the failure mode of #101 (`site`)
 * and #102 (`surecart-ecommerce`).
 *
 * This test is the mechanical safeguard. It compares the categories
 * surfaced by:
 *
 *   1. A captured live-catalog snapshot (`tests/fixtures/live-catalog-snapshot.json`)
 *      — categories observed against wickedevolutions.com (multisite) and
 *      helenawillow.com (single-site) on 2026-05-07. The snapshot is the
 *      pinned floor; if a category that shipped to operators is missing
 *      from the registry, this test fails loudly.
 *   2. A registry-derived enumeration (`ScopeRegistry::categories_from_registry()`)
 *      — categories surfaced by the in-memory ability registry the unit
 *      tests build from `wp_register_ability()` stubs. Future Composer-
 *      installed `abilities-for-*` packages register through the same path
 *      and will be picked up automatically.
 *
 * The "no false positive" phase lives in {@see test_uncategorized_synthetic_category_fails_coverage}:
 * inject a synthetic category that is not in the registry and assert the
 * coverage check fails. Pins that the test detects misses, not just
 * declares green when the snapshot happens to match.
 *
 * Source: Plans/Alpha Release Gate/Alpha Release Gate + Issue Reconciliation 2026-05-07.md (Phase B.1).
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\ScopeRegistry;

final class ScopeCoverageDriftTest extends TestCase {

	/**
	 * Path to the live-catalog snapshot fixture, relative to the repo root.
	 */
	private const SNAPSHOT_PATH = __DIR__ . '/../../../fixtures/live-catalog-snapshot.json';

	/**
	 * @return array{categories:string[],sample_abilities_per_category:array<string,string[]>}
	 */
	private function load_snapshot(): array {
		$raw = file_get_contents( self::SNAPSHOT_PATH );
		$this->assertIsString( $raw, 'Live catalog snapshot must exist at ' . self::SNAPSHOT_PATH );

		$decoded = json_decode( $raw, true );
		$this->assertIsArray( $decoded, 'Snapshot must be valid JSON.' );
		$this->assertArrayHasKey( 'categories', $decoded );
		$this->assertIsArray( $decoded['categories'] );

		return $decoded;
	}

	// ── Live catalog snapshot coverage (positive) ─────────────────────────

	public function test_every_snapshot_category_has_a_scope_in_registry(): void {
		$snapshot = $this->load_snapshot();

		$missing = array();
		foreach ( $snapshot['categories'] as $category ) {
			if ( ! ScopeRegistry::has_category_coverage( (string) $category ) ) {
				$missing[] = $category;
			}
		}

		$this->assertSame(
			array(),
			$missing,
			"ScopeRegistry is missing scopes for categories that are surfaced live:\n  - "
			. implode( "\n  - ", $missing )
			. "\n\nFix: add the category to ScopeRegistry::all_scopes() and (if read-only-only) "
			. "to UMBRELLA_IMPLICATIONS['abilities:read']. Then re-run this test."
		);
	}

	public function test_snapshot_includes_the_two_categories_the_hotfix_added(): void {
		// Pin the regression: #101 / #102 must remain in the snapshot so a
		// future "tidy-up" PR can't quietly remove them and re-open the
		// gap. The snapshot is the empirical proof, the registry coverage
		// is the fix, the test ties them together.
		$snapshot = $this->load_snapshot();

		$this->assertContains( 'site',                $snapshot['categories'], 'Issue #101 — `site` must remain in the live snapshot.' );
		$this->assertContains( 'surecart-ecommerce',  $snapshot['categories'], 'Issue #102 — `surecart-ecommerce` must remain in the live snapshot.' );
	}

	public function test_snapshot_categories_are_sorted_and_unique(): void {
		// Maintenance hygiene: when regenerating the snapshot, write it
		// sorted so diffs in PRs are clean and dedupe drift surfaces.
		$snapshot = $this->load_snapshot();
		$expected = $snapshot['categories'];

		$sorted = $expected;
		sort( $sorted );

		$this->assertSame( $sorted,                   $expected, 'Snapshot categories must be sorted ascending.' );
		$this->assertSame( count( $expected ),        count( array_unique( $expected ) ), 'Snapshot categories must be unique.' );
	}

	// ── Registry coverage of the two specific categories (#101, #102) ────

	public function test_site_scopes_are_registered_after_101_fix(): void {
		$scopes = ScopeRegistry::all_scopes();

		$this->assertContains( 'abilities:site:read', $scopes, 'Issue #101 acceptance — `abilities:site:read` must be grantable.' );
	}

	public function test_site_scope_is_implied_by_umbrella_read_after_101_fix(): void {
		// The issue's explicit acceptance: `abilities:read` must imply
		// `abilities:site:read` so a default operator grant covers
		// `core/get-site-info`. Mirrors the existing read-only-module
		// pattern (rest, site-health, diagnostic, editorial).
		$expanded = ScopeRegistry::expand( array( 'abilities:read' ) );
		$this->assertContains( 'abilities:site:read', $expanded );
	}

	public function test_site_is_read_only_module_in_registry(): void {
		// `core/get-site-info` and `core/get-environment-info` are the
		// only `site` abilities today, both reads. Pin that no
		// `:write`/`:delete` slipped in alongside the read scope — if
		// future site abilities need write/delete, that's an explicit
		// design choice the next PR must make, not an accidental sweep.
		$scopes = ScopeRegistry::all_scopes();
		$this->assertContains( 'abilities:site:read', $scopes );
		$this->assertNotContains( 'abilities:site:write',  $scopes, '`site` is read-only-only today; promote the module out of $read_only_modules to add write.' );
		$this->assertNotContains( 'abilities:site:delete', $scopes, '`site` is read-only-only today; promote the module out of $read_only_modules to add delete.' );
	}

	public function test_surecart_ecommerce_scopes_are_registered_after_102_fix(): void {
		$scopes = ScopeRegistry::all_scopes();

		$this->assertContains( 'abilities:surecart-ecommerce:read',   $scopes, 'Issue #102 acceptance — `surecart-ecommerce:read` must be grantable.' );
		$this->assertContains( 'abilities:surecart-ecommerce:write',  $scopes, 'Issue #102 acceptance — `surecart-ecommerce:write` must be grantable.' );
		$this->assertContains( 'abilities:surecart-ecommerce:delete', $scopes, 'Issue #102 acceptance — `surecart-ecommerce:delete` must be grantable.' );
	}

	public function test_surecart_ecommerce_scope_is_NOT_implied_by_global_umbrella(): void {
		// Per the #102 body's "explicit grant may be preferable" stance:
		// surecart-ecommerce sits in the suite-modules tier (next to
		// surecart, spectra, presto-player, astra, fluent-*) which is
		// outside the global umbrella. Operators must explicitly grant
		// the scope.
		$expanded = ScopeRegistry::expand( array( 'abilities:read' ) );
		$this->assertNotContains( 'abilities:surecart-ecommerce:read', $expanded );

		$expanded_w = ScopeRegistry::expand( array( 'abilities:write' ) );
		$this->assertNotContains( 'abilities:surecart-ecommerce:write', $expanded_w );
	}

	// ── Registry-derived coverage (in-memory abilities) ───────────────────

	public function test_registry_derived_categories_are_all_covered(): void {
		// When future tests register abilities via wp_register_ability(),
		// this test exercises the same coverage rule against the live
		// in-memory registry. Empty by default (no abilities registered),
		// so the assertion below is vacuously true under the unit-test
		// bootstrap — but a future test that registers an ability under
		// an unmapped category would surface it here without needing to
		// regenerate the snapshot.
		$registry_categories = ScopeRegistry::categories_from_registry();

		foreach ( $registry_categories as $category ) {
			$this->assertTrue(
				ScopeRegistry::has_category_coverage( (string) $category ),
				sprintf( 'In-memory ability registry surfaces unmapped category `%s`.', $category )
			);
		}
	}

	public function test_categories_from_registry_returns_sorted_unique_slugs(): void {
		// Inject a few abilities through the bootstrap stub registry and
		// assert the helper de-dupes + sorts. Reset state so we don't
		// pollute neighbouring tests.
		$prior                          = $GLOBALS['wp_test_abilities'] ?? array();
		$GLOBALS['wp_test_abilities']   = array();

		$mk = function ( string $name, string $cat ) {
			$a              = new \WP_Ability( $name, array( 'category' => $cat ) );
			$GLOBALS['wp_test_abilities'][ $name ] = $a;
		};

		$mk( 'foo/a', 'zeta' );
		$mk( 'foo/b', 'alpha' );
		$mk( 'foo/c', 'alpha' );
		$mk( 'foo/d', 'gamma' );

		$cats = ScopeRegistry::categories_from_registry();

		$this->assertSame( array( 'alpha', 'gamma', 'zeta' ), $cats );

		$GLOBALS['wp_test_abilities'] = $prior;
	}

	// ── No-false-positive phase ──────────────────────────────────────────

	public function test_uncategorized_synthetic_category_fails_coverage(): void {
		// Negative control — the test must REPORT a miss when one exists.
		// Inject a category the registry doesn't know about and assert
		// has_category_coverage() returns false. Without this, a green
		// run could mean "all categories covered" OR "the comparator is
		// broken and silently passing everything" — same surface signal,
		// very different reality.
		$this->assertFalse(
			ScopeRegistry::has_category_coverage( 'definitely-not-a-real-category-xyz' ),
			'Coverage helper must return false for an unknown category — otherwise the positive test is meaningless.'
		);
	}

	public function test_synthetic_uncovered_category_in_fixture_would_fail_coverage_test(): void {
		// Build the same coverage check the positive test runs, but with
		// an injected uncovered category. The check MUST surface it.
		// This proves the positive test ("every snapshot category has a
		// scope") is a real check, not a no-op.
		$synthetic = array_merge(
			$this->load_snapshot()['categories'],
			array( 'unmapped-experimental-category' )
		);

		$missing = array();
		foreach ( $synthetic as $category ) {
			if ( ! ScopeRegistry::has_category_coverage( (string) $category ) ) {
				$missing[] = $category;
			}
		}

		$this->assertSame(
			array( 'unmapped-experimental-category' ),
			$missing,
			'Coverage check must surface a synthetic uncovered category. If this fails, the positive coverage test is unsound.'
		);
	}

	public function test_empty_category_falls_back_to_mcp_adapter_and_is_covered(): void {
		// `OAuthScopeEnforcer::category_segment()` defaults missing
		// categories to `mcp-adapter`. The coverage helper preserves the
		// same fallback so a minimally-registered ability with no
		// category doesn't surface as a false miss.
		$this->assertTrue( ScopeRegistry::has_category_coverage( '' ) );
	}
}
