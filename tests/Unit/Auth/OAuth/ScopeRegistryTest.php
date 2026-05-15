<?php
/**
 * Tests for ScopeRegistry — canonical scope catalog and expansion rules.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\ScopeRegistry;

final class ScopeRegistryTest extends TestCase {

	// --- all_scopes ---

	public function test_all_scopes_returns_non_empty_array(): void {
		$scopes = ScopeRegistry::all_scopes();
		$this->assertNotEmpty( $scopes );
	}

	public function test_all_scopes_contains_umbrella_scopes(): void {
		$scopes = ScopeRegistry::all_scopes();
		$this->assertContains( 'abilities:read', $scopes );
		$this->assertContains( 'abilities:write', $scopes );
		$this->assertContains( 'abilities:delete', $scopes );
	}

	public function test_all_scopes_are_unique(): void {
		$scopes = ScopeRegistry::all_scopes();
		$this->assertSame( count( $scopes ), count( array_unique( $scopes ) ) );
	}

	// --- is_sensitive ---

	public function test_sensitive_scopes_are_flagged(): void {
		// Users and plugins are canonical sensitive modules.
		$this->assertTrue( ScopeRegistry::is_sensitive( 'abilities:users:read' ) );
		$this->assertTrue( ScopeRegistry::is_sensitive( 'abilities:users:write' ) );
		$this->assertTrue( ScopeRegistry::is_sensitive( 'abilities:plugins:write' ) );
	}

	public function test_non_sensitive_scope_not_flagged(): void {
		$this->assertFalse( ScopeRegistry::is_sensitive( 'abilities:read' ) );
		$this->assertFalse( ScopeRegistry::is_sensitive( 'abilities:content:read' ) );
	}

	// --- expand ---

	public function test_expand_umbrella_read_implies_non_sensitive_reads(): void {
		$expanded = ScopeRegistry::expand( [ 'abilities:read' ] );
		$this->assertContains( 'abilities:read', $expanded );
		$this->assertContains( 'abilities:content:read', $expanded );
	}

	public function test_expand_umbrella_read_does_not_imply_sensitive_scopes(): void {
		$expanded = ScopeRegistry::expand( [ 'abilities:read' ] );
		$this->assertNotContains( 'abilities:users:read', $expanded );
		$this->assertNotContains( 'abilities:plugins:read', $expanded );
	}

	public function test_expand_umbrella_write_does_not_imply_sensitive_write(): void {
		$expanded = ScopeRegistry::expand( [ 'abilities:write' ] );
		$this->assertNotContains( 'abilities:users:write', $expanded );
		$this->assertNotContains( 'abilities:plugins:write', $expanded );
	}

	public function test_expand_explicit_sensitive_scope_is_passed_through(): void {
		// Explicitly requested sensitive scopes must survive expansion.
		$expanded = ScopeRegistry::expand( [ 'abilities:users:read' ] );
		$this->assertContains( 'abilities:users:read', $expanded );
	}

	public function test_expand_multiple_umbrellas(): void {
		$expanded = ScopeRegistry::expand( [ 'abilities:read', 'abilities:write' ] );
		$this->assertContains( 'abilities:read', $expanded );
		$this->assertContains( 'abilities:write', $expanded );
		$this->assertContains( 'abilities:content:read', $expanded );
		$this->assertContains( 'abilities:content:write', $expanded );
	}

	public function test_expand_deduplicates_result(): void {
		// Passing the same scope twice should not produce duplicates.
		$expanded = ScopeRegistry::expand( [ 'abilities:read', 'abilities:read' ] );
		$this->assertSame( count( $expanded ), count( array_unique( $expanded ) ) );
	}

	// --- unknown_scopes ---

	public function test_unknown_scopes_returns_empty_for_valid_scopes(): void {
		$unknown = ScopeRegistry::unknown_scopes( [ 'abilities:read', 'abilities:write' ] );
		$this->assertEmpty( $unknown );
	}

	public function test_unknown_scopes_returns_unknown(): void {
		$unknown = ScopeRegistry::unknown_scopes( [ 'abilities:read', 'abilities:bogus:scope' ] );
		$this->assertContains( 'abilities:bogus:scope', $unknown );
		$this->assertNotContains( 'abilities:read', $unknown );
	}

	// --- Fluent suite scopes (#74) ---

	/**
	 * Every Fluent module category registered in abilities-for-fluent-plugins
	 * must have a matching scope group in the registry, otherwise OAuth-bound
	 * Fluent ability calls fail with insufficient_scope at execute time.
	 */
	public function test_fluent_per_module_scopes_are_registered(): void {
		$modules = [
			'fluent-crm', 'fluent-community', 'fluent-forms', 'fluent-support',
			'fluent-boards', 'fluent-booking', 'fluent-smtp', 'fluent-auth',
			'fluent-snippets', 'fluent-messaging', 'fluent-cart', 'fluent-affiliate',
			'fluent-player',
		];
		$scopes  = ScopeRegistry::all_scopes();

		foreach ( $modules as $m ) {
			$this->assertContains( "abilities:{$m}:read",   $scopes, "{$m} read scope must be registered" );
			$this->assertContains( "abilities:{$m}:write",  $scopes, "{$m} write scope must be registered" );
			$this->assertContains( "abilities:{$m}:delete", $scopes, "{$m} delete scope must be registered" );
		}
	}

	public function test_fluent_cross_module_scopes_are_registered(): void {
		// Cross-module Fluent abilities (e.g. fluent-get-user-360, fluent-get-suite-dashboard)
		// register under the 'fluent' category and require abilities:fluent:<op>.
		$scopes = ScopeRegistry::all_scopes();
		$this->assertContains( 'abilities:fluent:read',   $scopes );
		$this->assertContains( 'abilities:fluent:write',  $scopes );
		$this->assertContains( 'abilities:fluent:delete', $scopes );
	}

	public function test_fluent_scopes_are_not_sensitive(): void {
		// Fluent scopes follow the existing third-party suite pattern
		// (spectra/presto-player/surecart/astra) — explicit per-module grant
		// required, but not subject to the sensitive-scope rule that bans
		// umbrella implication.
		$this->assertFalse( ScopeRegistry::is_sensitive( 'abilities:fluent-crm:read' ) );
		$this->assertFalse( ScopeRegistry::is_sensitive( 'abilities:fluent:read' ) );
	}

	public function test_global_umbrella_does_not_imply_fluent_scopes(): void {
		// Matches the existing suite pattern: abilities:read does NOT imply
		// abilities:spectra:read, so it must not imply abilities:fluent-crm:read
		// either. Operators must explicitly request a Fluent scope.
		$expanded = ScopeRegistry::expand( [ 'abilities:read' ] );
		$this->assertNotContains( 'abilities:fluent-crm:read',     $expanded );
		$this->assertNotContains( 'abilities:fluent-community:read', $expanded );
		$this->assertNotContains( 'abilities:fluent:read',         $expanded );
	}
}
