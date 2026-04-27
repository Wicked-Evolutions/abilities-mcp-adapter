<?php
/**
 * Regression test: AuthorizationServer::is_well_known_or_oauth_path()
 * must not fatal on missing or empty REQUEST_URI.
 *
 * Phase 6 deploy caught: strtok('', '?') returns false on PHP 8.2+,
 * which then crashes str_starts_with(false, …). Fatal during early
 * request lifecycle on sites where REQUEST_URI is unset or empty.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationServer;

final class IsWellKnownOrOAuthPathTest extends TestCase {

	private function call(): bool {
		// is_well_known_or_oauth_path is private — invoke via reflection.
		// (setAccessible is unnecessary on PHP 8.1+ and deprecated on 8.5.)
		$ref = new \ReflectionClass( AuthorizationServer::class );
		$m   = $ref->getMethod( 'is_well_known_or_oauth_path' );
		return $m->invoke( null );
	}

	protected function tearDown(): void {
		unset( $_SERVER['REQUEST_URI'] );
	}

	public function test_unset_request_uri_returns_false(): void {
		unset( $_SERVER['REQUEST_URI'] );
		$this->assertFalse( $this->call() );
	}

	public function test_empty_string_request_uri_returns_false(): void {
		$_SERVER['REQUEST_URI'] = '';
		$this->assertFalse( $this->call() );
	}

	public function test_non_string_request_uri_returns_false(): void {
		// Hostile / corrupted superglobal — still must not fatal.
		$_SERVER['REQUEST_URI'] = false;
		$this->assertFalse( $this->call() );
	}

	public function test_root_returns_false(): void {
		$_SERVER['REQUEST_URI'] = '/';
		$this->assertFalse( $this->call() );
	}

	public function test_well_known_oauth_resource_returns_true(): void {
		$_SERVER['REQUEST_URI'] = '/.well-known/oauth-protected-resource';
		$this->assertTrue( $this->call() );
	}

	public function test_oauth_authorize_returns_true(): void {
		$_SERVER['REQUEST_URI'] = '/oauth/authorize';
		$this->assertTrue( $this->call() );
	}

	public function test_oauth_path_with_query_returns_true(): void {
		$_SERVER['REQUEST_URI'] = '/oauth/authorize?response_type=code&client_id=abc';
		$this->assertTrue( $this->call() );
	}

	public function test_unrelated_path_returns_false(): void {
		$_SERVER['REQUEST_URI'] = '/wp-admin/edit.php';
		$this->assertFalse( $this->call() );
	}

	public function test_path_starting_with_oauth_substring_but_not_oauth_prefix_returns_false(): void {
		// /oauthish-something — must not match /oauth/ prefix.
		$_SERVER['REQUEST_URI'] = '/oauthlike/foo';
		$this->assertFalse( $this->call() );
	}
}
