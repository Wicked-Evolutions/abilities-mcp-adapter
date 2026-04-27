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
}
