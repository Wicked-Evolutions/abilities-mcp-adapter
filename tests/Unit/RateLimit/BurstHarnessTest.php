<?php
/**
 * Unit tests for BurstHarness pure helpers (#27).
 *
 * Wire-level burst behavior is exercised by `bin/rate-limit-burst.php` against
 * a live install. These tests pin the parsing + classification logic the
 * harness depends on, so a regression in either lands at unit-test time
 * rather than at the next operator-run burst.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\RateLimit
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\RateLimit;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\RateLimit\BurstHarness;

final class BurstHarnessTest extends TestCase {

	// ─── parse_response ─────────────────────────────────────────────────────────

	public function test_parse_response_extracts_status_headers_and_body(): void {
		$raw = "HTTP/1.1 200 OK\r\n"
			. "Content-Type: application/json\r\n"
			. "Mcp-Session-Id: abc-123\r\n"
			. "\r\n"
			. '{"ok":true}';

		$parsed = BurstHarness::parse_response( $raw );

		$this->assertSame( 200, $parsed['status'] );
		$this->assertSame( 'application/json', $parsed['headers']['content-type'] );
		$this->assertSame( 'abc-123', $parsed['headers']['mcp-session-id'] );
		$this->assertSame( '{"ok":true}', $parsed['body'] );
	}

	public function test_parse_response_lowercases_header_names(): void {
		// HTTP/1.x header names are case-insensitive; normalize for predictable lookup.
		$raw    = "HTTP/1.1 200 OK\r\nMCP-SESSION-ID: x\r\n\r\nbody";
		$parsed = BurstHarness::parse_response( $raw );
		$this->assertSame( 'x', $parsed['headers']['mcp-session-id'] );
	}

	public function test_parse_response_skips_100_continue(): void {
		$raw = "HTTP/1.1 100 Continue\r\n\r\n"
			. "HTTP/1.1 429 Too Many Requests\r\n"
			. "Retry-After: 7\r\n"
			. "\r\n"
			. '{"error":"rate"}';

		$parsed = BurstHarness::parse_response( $raw );

		$this->assertSame( 429, $parsed['status'] );
		$this->assertSame( '7', $parsed['headers']['retry-after'] );
	}

	public function test_parse_response_preserves_body_with_blank_lines(): void {
		// Only the FIRST CRLFCRLF separates headers from body; later blank
		// lines belong to the body and must survive intact.
		$raw = "HTTP/1.1 200 OK\r\n\r\nfirst\r\n\r\nsecond";

		$parsed = BurstHarness::parse_response( $raw );

		$this->assertSame( 200, $parsed['status'] );
		$this->assertSame( "first\r\n\r\nsecond", $parsed['body'] );
	}

	// ─── extract_session / merge_session ───────────────────────────────────────

	public function test_extract_session_pulls_id_and_token(): void {
		$response = array( 'headers' => array(
			'mcp-session-id'    => 'sess-1',
			'mcp-session-token' => 'tok-1',
		) );
		$this->assertSame( array( 'session_id' => 'sess-1', 'session_token' => 'tok-1' ), BurstHarness::extract_session( $response ) );
	}

	public function test_extract_session_returns_nulls_when_headers_absent(): void {
		$this->assertSame(
			array( 'session_id' => null, 'session_token' => null ),
			BurstHarness::extract_session( array( 'headers' => array() ) )
		);
	}

	public function test_merge_session_prefers_observed_over_current(): void {
		// Defensive against future per-request token rotation: if the server
		// emits a fresh token, the harness must echo the new one back next.
		$current  = array( 'session_id' => 'sess-1', 'session_token' => 'tok-1' );
		$observed = array( 'session_id' => 'sess-1', 'session_token' => 'tok-2' );

		$this->assertSame(
			array( 'session_id' => 'sess-1', 'session_token' => 'tok-2' ),
			BurstHarness::merge_session( $current, $observed )
		);
	}

	public function test_merge_session_keeps_current_when_observed_omits_value(): void {
		// Server may omit headers on later responses; harness must not
		// drop the session id/token just because one response was bare.
		$current  = array( 'session_id' => 'sess-1', 'session_token' => 'tok-1' );
		$observed = array( 'session_id' => null,     'session_token' => null );

		$this->assertSame( $current, BurstHarness::merge_session( $current, $observed ) );
	}

	// ─── classify_threshold_trip ────────────────────────────────────────────────

	private function ok( int $count ): array {
		return array_fill( 0, $count, array( 'status' => 200, 'retry_after' => null ) );
	}

	private function denied( int $count, int $retry = 17 ): array {
		return array_fill( 0, $count, array( 'status' => 429, 'retry_after' => $retry ) );
	}

	public function test_classify_clean_trip_at_threshold_passes(): void {
		// 60 OK + 5 429s with positive Retry-After — the canonical "passes" case.
		$results = array_merge( $this->ok( 60 ), $this->denied( 5 ) );
		$verdict = BurstHarness::classify_threshold_trip( $results, 60 );

		$this->assertTrue( $verdict['passed'] );
		$this->assertSame( 60, $verdict['first_429_index'] );
		$this->assertSame( array(), $verdict['reasons'] );
	}

	public function test_classify_no_trip_fails(): void {
		// All 65 succeeded — limiter never tripped.
		$results = $this->ok( 65 );
		$verdict = BurstHarness::classify_threshold_trip( $results, 60 );

		$this->assertFalse( $verdict['passed'] );
		$this->assertNull( $verdict['first_429_index'] );
		$this->assertNotEmpty( $verdict['reasons'] );
	}

	public function test_classify_premature_trip_fails(): void {
		// First 429 at index 30 instead of 60 — limiter trips early.
		$results = array_merge( $this->ok( 30 ), $this->denied( 35 ) );
		$verdict = BurstHarness::classify_threshold_trip( $results, 60 );

		$this->assertFalse( $verdict['passed'] );
		$this->assertSame( 30, $verdict['first_429_index'] );
		$this->assertNotEmpty( $verdict['reasons'] );
	}

	public function test_classify_429_without_retry_after_fails(): void {
		$bad     = array( 'status' => 429, 'retry_after' => null );
		$results = array_merge( $this->ok( 60 ), array( $bad ) );
		$verdict = BurstHarness::classify_threshold_trip( $results, 60 );

		$this->assertFalse( $verdict['passed'] );
		$this->assertNotEmpty( $verdict['reasons'] );
	}

	public function test_classify_initialize_threshold_30_passes(): void {
		// Initialize uses a tighter window — verify the helper is threshold-agnostic.
		$results = array_merge( $this->ok( 30 ), $this->denied( 1 ) );
		$verdict = BurstHarness::classify_threshold_trip( $results, 30 );

		$this->assertTrue( $verdict['passed'] );
		$this->assertSame( 30, $verdict['first_429_index'] );
	}

	// ─── body builders ──────────────────────────────────────────────────────────

	public function test_build_tools_call_body_is_valid_jsonrpc(): void {
		$body = BurstHarness::build_tools_call_body( 42 );
		$decoded = json_decode( $body, true );

		$this->assertSame( '2.0', $decoded['jsonrpc'] );
		$this->assertSame( 42, $decoded['id'] );
		$this->assertSame( 'tools/call', $decoded['method'] );
		$this->assertSame( 'mcp-adapter/list-resources', $decoded['params']['name'] );
	}

	public function test_build_initialize_body_is_valid_jsonrpc(): void {
		$body    = BurstHarness::build_initialize_body( 1 );
		$decoded = json_decode( $body, true );

		$this->assertSame( '2.0', $decoded['jsonrpc'] );
		$this->assertSame( 1, $decoded['id'] );
		$this->assertSame( 'initialize', $decoded['method'] );
		$this->assertSame( 'rate-limit-burst-harness', $decoded['params']['clientInfo']['name'] );
	}
}
