<?php
/**
 * Tests for AuthorizationCodeStore pure-logic methods.
 *
 * DB-dependent methods (store, consume) require integration setup.
 * compute_challenge() is pure and fully unit-testable.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationCodeStore;

final class AuthorizationCodeStoreTest extends TestCase {

	// --- PKCE S256 challenge computation (H.1.1) ---

	public function test_compute_challenge_matches_rfc7636_s256(): void {
		// RFC 7636 test vector.
		$verifier  = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
		$expected  = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
		$challenge = AuthorizationCodeStore::compute_challenge( $verifier );

		$this->assertSame( $expected, $challenge );
	}

	public function test_compute_challenge_different_verifiers_produce_different_challenges(): void {
		$c1 = AuthorizationCodeStore::compute_challenge( 'verifier_one_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' );
		$c2 = AuthorizationCodeStore::compute_challenge( 'verifier_two_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' );

		$this->assertNotSame( $c1, $c2 );
	}

	public function test_compute_challenge_is_base64url_without_padding(): void {
		$verifier  = str_repeat( 'a', 43 ); // minimum allowed length per RFC 7636.
		$challenge = AuthorizationCodeStore::compute_challenge( $verifier );

		// Must not contain '+', '/', or '=' (base64url, no padding).
		$this->assertStringNotContainsString( '+', $challenge );
		$this->assertStringNotContainsString( '/', $challenge );
		$this->assertStringNotContainsString( '=', $challenge );
	}
}
