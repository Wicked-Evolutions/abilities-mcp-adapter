<?php
/**
 * #89: StdioServerBridge::request_id_state() — JSON-RPC id state extraction.
 *
 * Pins the boundary between two structurally similar but semantically
 * distinct JSON-RPC 2.0 §4 conditions:
 *
 *   - `id` member ABSENT     → notification; server MUST NOT respond.
 *   - `id` member PRESENT    → request; server MUST respond, including
 *                              when the value is literal null.
 *
 * Pre-fix the bridge collapsed both via `$request['id'] ?? null` and treated
 * them as notifications, hanging spec-compliant clients sending id:null.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Cli
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Cli;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Cli\StdioServerBridge;

final class RequestIdStateTest extends TestCase {

	public function test_absent_id_is_notification(): void {
		$state = StdioServerBridge::request_id_state( array( 'jsonrpc' => '2.0', 'method' => 'test' ) );
		$this->assertFalse( $state['has_id'] );
		$this->assertNull( $state['id'] );
	}

	public function test_explicit_null_id_is_request(): void {
		// The fix — pre-#89 this case was indistinguishable from a notification.
		$state = StdioServerBridge::request_id_state( array( 'jsonrpc' => '2.0', 'method' => 'test', 'id' => null ) );
		$this->assertTrue( $state['has_id'], 'id:null must be a request, not a notification (JSON-RPC §4)' );
		$this->assertNull( $state['id'] );
	}

	public function test_int_id_is_request(): void {
		$state = StdioServerBridge::request_id_state( array( 'id' => 7 ) );
		$this->assertTrue( $state['has_id'] );
		$this->assertSame( 7, $state['id'] );
	}

	public function test_string_id_is_request(): void {
		$state = StdioServerBridge::request_id_state( array( 'id' => '7-abc' ) );
		$this->assertTrue( $state['has_id'] );
		$this->assertSame( '7-abc', $state['id'] );
	}

	public function test_zero_id_is_request_not_notification(): void {
		// `0` is falsy in PHP — easy to misclassify under loose checks. JSON-RPC
		// §4 doesn't preclude id:0; pin it as a valid request.
		$state = StdioServerBridge::request_id_state( array( 'id' => 0 ) );
		$this->assertTrue( $state['has_id'] );
		$this->assertSame( 0, $state['id'] );
	}

	public function test_empty_string_id_is_request(): void {
		// JSON-RPC §3 allows string ids; spec doesn't forbid empty string.
		// Loose `if ( $id )` would misclassify as notification.
		$state = StdioServerBridge::request_id_state( array( 'id' => '' ) );
		$this->assertTrue( $state['has_id'] );
		$this->assertSame( '', $state['id'] );
	}

	public function test_bool_false_id_is_treated_as_request_value(): void {
		// Spec only allows string/number/null for id, but a malformed client
		// could send false. The helper's job is structural extraction (member
		// presence + value passthrough), not value-type validation. Downstream
		// code can reject non-spec types after this.
		$state = StdioServerBridge::request_id_state( array( 'id' => false ) );
		$this->assertTrue( $state['has_id'] );
		$this->assertFalse( $state['id'] );
	}
}
