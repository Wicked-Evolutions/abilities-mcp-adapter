<?php
/**
 * Tests for BoundaryEventEmitter — focused on the api_key hashing contract.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Infrastructure\Observability;

use WickedEvolutions\McpAdapter\Infrastructure\Observability\BoundaryEventEmitter;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class BoundaryEventEmitterTest extends TestCase {

	public function test_raw_api_key_is_dropped_from_sanitized_tags(): void {
		$out = BoundaryEventEmitter::sanitize( array(
			'severity' => 'warn',
			'api_key'  => 'sk_live_super_secret_value',
		) );
		$this->assertArrayNotHasKey( 'api_key', $out );
	}

	public function test_raw_api_key_is_replaced_with_sha256_hash(): void {
		$key = 'sk_live_super_secret_value';
		$out = BoundaryEventEmitter::sanitize( array(
			'api_key' => $key,
		) );
		$this->assertArrayHasKey( 'api_key_hash', $out );
		$this->assertSame( hash( 'sha256', $key ), $out['api_key_hash'] );
	}

	public function test_explicit_api_key_hash_wins_over_derived(): void {
		// Caller already hashed the key with their own scheme — don't overwrite it.
		$out = BoundaryEventEmitter::sanitize( array(
			'api_key'      => 'sk_live_secret',
			'api_key_hash' => 'caller_supplied_hash',
		) );
		$this->assertSame( 'caller_supplied_hash', $out['api_key_hash'] );
	}

	public function test_empty_api_key_does_not_produce_hash(): void {
		$out = BoundaryEventEmitter::sanitize( array(
			'api_key' => '',
		) );
		$this->assertArrayNotHasKey( 'api_key', $out );
		$this->assertArrayNotHasKey( 'api_key_hash', $out );
	}

	public function test_non_string_api_key_does_not_produce_hash(): void {
		$out = BoundaryEventEmitter::sanitize( array(
			'api_key' => 12345,
		) );
		$this->assertArrayNotHasKey( 'api_key', $out );
		$this->assertArrayNotHasKey( 'api_key_hash', $out );
	}

	public function test_other_allowlisted_tags_pass_through(): void {
		$out = BoundaryEventEmitter::sanitize( array(
			'severity'   => 'warn',
			'method'     => 'tools/list',
			'api_key'    => 'sk_test',
			'session_id' => 'abc-123',
		) );
		$this->assertSame( 'warn', $out['severity'] );
		$this->assertSame( 'tools/list', $out['method'] );
		$this->assertSame( 'abc-123', $out['session_id'] );
		$this->assertSame( hash( 'sha256', 'sk_test' ), $out['api_key_hash'] );
	}

	public function test_unknown_tags_still_dropped(): void {
		$out = BoundaryEventEmitter::sanitize( array(
			'severity'      => 'warn',
			'request_body'  => 'should be dropped',
			'response_body' => 'also dropped',
		) );
		$this->assertArrayNotHasKey( 'request_body', $out );
		$this->assertArrayNotHasKey( 'response_body', $out );
	}
}
