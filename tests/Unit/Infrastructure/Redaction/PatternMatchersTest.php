<?php

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Infrastructure\Redaction;

use WickedEvolutions\McpAdapter\Infrastructure\Redaction\PatternMatchers;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class PatternMatchersTest extends TestCase {

	// ── is_password_hash ──────────────────────────────────────────────────────

	public function test_password_hash_phpass(): void {
		$this->assertTrue( PatternMatchers::is_password_hash( '$P$Bsomethinghashy123' ) );
		$this->assertTrue( PatternMatchers::is_password_hash( '$H$9abcdef' ) );
	}

	public function test_password_hash_bcrypt(): void {
		$this->assertTrue( PatternMatchers::is_password_hash( '$2a$12$abc' ) );
		$this->assertTrue( PatternMatchers::is_password_hash( '$2b$12$abc' ) );
		$this->assertTrue( PatternMatchers::is_password_hash( '$2y$12$abc' ) );
	}

	public function test_password_hash_modern(): void {
		$this->assertTrue( PatternMatchers::is_password_hash( '$argon2id$v=19$m=65536' ) );
		$this->assertTrue( PatternMatchers::is_password_hash( '$pbkdf2$1000$abc' ) );
		$this->assertTrue( PatternMatchers::is_password_hash( '$scrypt$N=1024' ) );
	}

	public function test_password_hash_negatives(): void {
		$this->assertFalse( PatternMatchers::is_password_hash( '' ) );
		$this->assertFalse( PatternMatchers::is_password_hash( 'hunter2' ) );
		$this->assertFalse( PatternMatchers::is_password_hash( null ) );
		$this->assertFalse( PatternMatchers::is_password_hash( 12345 ) );
		$this->assertFalse( PatternMatchers::is_password_hash( array( '$P$' ) ) );
	}

	// ── is_known_api_key ──────────────────────────────────────────────────────

	public function test_known_api_key_stripe(): void {
		$this->assertTrue( PatternMatchers::is_known_api_key( 'sk_live_abc' ) );
		$this->assertTrue( PatternMatchers::is_known_api_key( 'sk_test_abc' ) );
		$this->assertTrue( PatternMatchers::is_known_api_key( 'pk_live_abc' ) );
		$this->assertTrue( PatternMatchers::is_known_api_key( 'pk_test_abc' ) );
	}

	public function test_known_api_key_slack(): void {
		$this->assertTrue( PatternMatchers::is_known_api_key( 'xoxb-1234-5678' ) );
		$this->assertTrue( PatternMatchers::is_known_api_key( 'xoxp-1234-5678' ) );
	}

	public function test_known_api_key_github(): void {
		$this->assertTrue( PatternMatchers::is_known_api_key( 'ghp_abcdef' ) );
		$this->assertTrue( PatternMatchers::is_known_api_key( 'gho_abcdef' ) );
		$this->assertTrue( PatternMatchers::is_known_api_key( 'ghu_abcdef' ) );
		$this->assertTrue( PatternMatchers::is_known_api_key( 'ghs_abcdef' ) );
		$this->assertTrue( PatternMatchers::is_known_api_key( 'ghr_abcdef' ) );
	}

	public function test_known_api_key_aws(): void {
		$this->assertTrue( PatternMatchers::is_known_api_key( 'AKIAIOSFODNN7EXAMPLE' ) );
		// Wrong length:
		$this->assertFalse( PatternMatchers::is_known_api_key( 'AKIAIOSF' ) );
	}

	public function test_known_api_key_google(): void {
		// AIza + 35 url-safe chars (documented Google API key format).
		$key = 'AIza' . str_pad( 'A', 35, 'b' );
		$this->assertSame( 39, strlen( $key ) );
		$this->assertTrue( PatternMatchers::is_known_api_key( $key ) );

		// Wrong length (34 chars after prefix) → no match.
		$this->assertFalse( PatternMatchers::is_known_api_key( 'AIza' . str_pad( '', 34, 'b' ) ) );
	}

	public function test_known_api_key_negatives(): void {
		$this->assertFalse( PatternMatchers::is_known_api_key( '' ) );
		$this->assertFalse( PatternMatchers::is_known_api_key( 'hello' ) );
		$this->assertFalse( PatternMatchers::is_known_api_key( null ) );
		$this->assertFalse( PatternMatchers::is_known_api_key( 12345 ) );
	}

	// ── passes_luhn ───────────────────────────────────────────────────────────

	public function test_luhn_valid_test_pans(): void {
		$this->assertTrue( PatternMatchers::passes_luhn( '4242424242424242' ) ); // Stripe test Visa.
		$this->assertTrue( PatternMatchers::passes_luhn( '5555555555554444' ) ); // Stripe test Mastercard.
		$this->assertTrue( PatternMatchers::passes_luhn( '378282246310005' ) );  // Amex test.
	}

	public function test_luhn_invalid_inputs(): void {
		$this->assertFalse( PatternMatchers::passes_luhn( '4242424242424241' ) ); // off by one.
		$this->assertFalse( PatternMatchers::passes_luhn( '12345' ) );             // too short.
		$this->assertFalse( PatternMatchers::passes_luhn( '12345678901234567890' ) ); // too long (20 digits).
		$this->assertFalse( PatternMatchers::passes_luhn( '4242-4242-4242-4242' ) );  // hyphens not stripped.
		$this->assertFalse( PatternMatchers::passes_luhn( ' 4242424242424242' ) );    // leading space.
		$this->assertFalse( PatternMatchers::passes_luhn( '' ) );
		$this->assertFalse( PatternMatchers::passes_luhn( null ) );
		$this->assertFalse( PatternMatchers::passes_luhn( 4242424242424242 ) );       // integer, not string.
	}

	public function test_luhn_minimum_length_13(): void {
		// 13-digit number that passes Luhn.
		$this->assertTrue( PatternMatchers::passes_luhn( '4222222222222' ) );
	}
}
