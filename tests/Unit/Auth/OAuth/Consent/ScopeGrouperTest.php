<?php
/**
 * Tests for ScopeGrouper — pure visual grouping.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\ScopeGrouper;

final class ScopeGrouperTest extends TestCase {

	public function test_groups_scopes_by_module(): void {
		$groups = ScopeGrouper::group( array(
			'abilities:content:read',
			'abilities:content:write',
			'abilities:taxonomies:read',
		) );
		$this->assertSame( array( 'abilities:content:read', 'abilities:content:write' ), $groups['content'] );
		$this->assertSame( array( 'abilities:taxonomies:read' ), $groups['taxonomies'] );
	}

	public function test_umbrella_scopes_group_under_umbrella_key(): void {
		$groups = ScopeGrouper::group( array( 'abilities:read', 'abilities:write' ) );
		$this->assertSame( array( 'abilities:read', 'abilities:write' ), $groups['umbrella'] );
	}

	public function test_umbrella_renders_first_then_modules_alphabetically(): void {
		$groups = ScopeGrouper::group( array(
			'abilities:taxonomies:read',
			'abilities:read',
			'abilities:content:read',
		) );
		$keys = array_keys( $groups );
		$this->assertSame( 'umbrella', $keys[0] );
		$this->assertSame( array( 'umbrella', 'content', 'taxonomies' ), $keys );
	}

	public function test_group_is_sensitive_returns_true_when_any_scope_is_sensitive(): void {
		$this->assertTrue( ScopeGrouper::group_is_sensitive( array( 'abilities:settings:read' ) ) );
		$this->assertTrue( ScopeGrouper::group_is_sensitive( array( 'abilities:content:read', 'abilities:settings:read' ) ) );
	}

	public function test_group_is_sensitive_returns_false_for_all_non_sensitive_scopes(): void {
		$this->assertFalse( ScopeGrouper::group_is_sensitive( array( 'abilities:content:read', 'abilities:content:write' ) ) );
	}
}
