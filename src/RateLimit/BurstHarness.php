<?php
/**
 * Session-aware rate-limit burst harness (#27).
 *
 * Exercises the live `/wp-json/mcp/mcp-adapter-default-server` endpoint
 * past its IP / user / initialize windows and verifies the wire response
 * matches the limiter contract (429 + Retry-After + boundary log entry).
 *
 * The harness is the dev-side complement to `RateLimiter`'s 33 unit cases
 * — those pin the in-memory math; this pins the actual wire behavior on
 * a live install. CLI entry point: bin/rate-limit-burst.php.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\RateLimit
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\RateLimit;

/**
 * Runs scripted bursts against a live MCP endpoint and classifies the result.
 *
 * The harness is intentionally a thin transport layer over `curl` plus pure
 * helpers for header parsing and verdict classification. The pure helpers are
 * unit-testable; the wire-level burst is exercised by operator-run CLI.
 */
final class BurstHarness {

	/** Default expected post-auth IP limit (matches `RateLimiter::DEFAULT_LIMIT_IP`). */
	public const DEFAULT_THRESHOLD = 60;

	/** Default expected initialize-only IP limit. */
	public const DEFAULT_INITIALIZE_THRESHOLD = 30;

	/**
	 * Parse a raw HTTP response into status, headers, and body.
	 *
	 * Tolerates 1xx informational responses (skips them and parses the next),
	 * lower- or upper-case header names, and bodies containing CRLFCRLF
	 * sequences (only the first \r\n\r\n separates headers from body).
	 *
	 * @return array{status:int, headers:array<string,string>, body:string}
	 */
	public static function parse_response( string $raw ): array {
		// Skip any 1xx/100-continue interim responses curl includes verbatim.
		while ( true ) {
			$split = preg_split( "/\r?\n\r?\n/", $raw, 2 );
			if ( ! is_array( $split ) || count( $split ) !== 2 ) {
				return array( 'status' => 0, 'headers' => array(), 'body' => $raw );
			}
			[ $head, $rest ] = $split;
			$status_line     = strtok( $head, "\r\n" );
			if ( ! is_string( $status_line ) ) {
				return array( 'status' => 0, 'headers' => array(), 'body' => $rest );
			}
			if ( preg_match( '#^HTTP/[\d.]+\s+(\d{3})#', $status_line, $m ) ) {
				$status = (int) $m[1];
				if ( $status >= 100 && $status < 200 ) {
					$raw = $rest;
					continue;
				}
			} else {
				return array( 'status' => 0, 'headers' => array(), 'body' => $rest );
			}

			$headers = array();
			foreach ( preg_split( "/\r?\n/", $head ) ?: array() as $line ) {
				if ( false === strpos( $line, ':' ) ) {
					continue;
				}
				[ $k, $v ] = explode( ':', $line, 2 );
				$headers[ strtolower( trim( $k ) ) ] = trim( $v );
			}
			return array(
				'status'  => $status,
				'headers' => $headers,
				'body'    => $rest,
			);
		}
	}

	/**
	 * Return the session id + session token from a parsed response, if present.
	 *
	 * The server emits both on every response (initialize emits a fresh pair;
	 * subsequent responses replay the same token but defensively re-read in
	 * case a future change rotates per-request).
	 *
	 * @param array{headers:array<string,string>} $response
	 * @return array{session_id:string|null, session_token:string|null}
	 */
	public static function extract_session( array $response ): array {
		$headers = $response['headers'] ?? array();
		return array(
			'session_id'    => isset( $headers['mcp-session-id'] ) ? (string) $headers['mcp-session-id'] : null,
			'session_token' => isset( $headers['mcp-session-token'] ) ? (string) $headers['mcp-session-token'] : null,
		);
	}

	/**
	 * Update an existing session pair from a fresh response, preserving
	 * existing values if the response omits them. This is what makes the
	 * harness session-aware: token may rotate, id should stay stable; the
	 * harness echoes the latest of each on the next request.
	 *
	 * @param array{session_id:string|null,session_token:string|null} $current
	 * @param array{session_id:string|null,session_token:string|null} $observed
	 * @return array{session_id:string|null,session_token:string|null}
	 */
	public static function merge_session( array $current, array $observed ): array {
		return array(
			'session_id'    => $observed['session_id']    ?? $current['session_id']    ?? null,
			'session_token' => $observed['session_token'] ?? $current['session_token'] ?? null,
		);
	}

	/**
	 * Classify a sequence of (status, retry_after) tuples against a threshold.
	 *
	 * Expected pattern for a clean threshold-trip burst:
	 *   - First $threshold responses are 2xx (or any non-429).
	 *   - The (threshold + 1)th response and beyond are 429.
	 *   - Every 429 carries a positive Retry-After.
	 *
	 * @param array<int, array{status:int, retry_after:int|null}> $results
	 *        In request order.
	 * @param int $threshold Expected limit (e.g. 60 for IP, 30 for initialize).
	 * @return array{
	 *   passed: bool,
	 *   first_429_index: int|null,
	 *   reasons: string[]
	 * }
	 */
	public static function classify_threshold_trip( array $results, int $threshold ): array {
		$reasons         = array();
		$first_429_index = null;

		foreach ( $results as $i => $r ) {
			if ( 429 === ( $r['status'] ?? 0 ) ) {
				$first_429_index = $i;
				break;
			}
		}

		if ( null === $first_429_index ) {
			$reasons[] = sprintf(
				'Burst of %d requests produced no 429 — limiter never tripped (expected trip after %d).',
				count( $results ),
				$threshold
			);
			return array( 'passed' => false, 'first_429_index' => null, 'reasons' => $reasons );
		}

		// Off-by-one tolerance: spec says "61st response is 429" when threshold is 60,
		// so first_429_index (zero-indexed) must equal $threshold.
		if ( $first_429_index !== $threshold ) {
			$reasons[] = sprintf(
				'First 429 at index %d (zero-based); expected at index %d.',
				$first_429_index,
				$threshold
			);
		}

		// Every request before the trip should be non-429.
		for ( $i = 0; $i < $first_429_index; $i++ ) {
			if ( 429 === ( $results[ $i ]['status'] ?? 0 ) ) {
				$reasons[] = sprintf( 'Premature 429 at index %d (before threshold).', $i );
				break;
			}
		}

		// Every 429 must carry a positive Retry-After.
		for ( $i = $first_429_index; $i < count( $results ); $i++ ) {
			if ( 429 !== ( $results[ $i ]['status'] ?? 0 ) ) {
				continue;
			}
			$retry = $results[ $i ]['retry_after'] ?? null;
			if ( null === $retry || $retry < 1 ) {
				$reasons[] = sprintf( '429 at index %d lacks a positive Retry-After.', $i );
				break;
			}
		}

		return array(
			'passed'          => empty( $reasons ),
			'first_429_index' => $first_429_index,
			'reasons'         => $reasons,
		);
	}

	/**
	 * Build a JSON-RPC body for a `tools/call` against the meta-tool.
	 *
	 * `mcp-adapter/list-resources` is intentionally chosen because it has no
	 * side effects, doesn't require sensitive scopes, and never persists state
	 * — safe to fire 65 times in a tight burst against a live install.
	 *
	 * @param int $request_id JSON-RPC id (must be unique per request).
	 */
	public static function build_tools_call_body( int $request_id ): string {
		return (string) json_encode( array(
			'jsonrpc' => '2.0',
			'id'      => $request_id,
			'method'  => 'tools/call',
			'params'  => array(
				'name'      => 'mcp-adapter/list-resources',
				'arguments' => new \stdClass(),
			),
		) );
	}

	/**
	 * Build a JSON-RPC body for an `initialize` request.
	 *
	 * @param int $request_id JSON-RPC id.
	 */
	public static function build_initialize_body( int $request_id ): string {
		return (string) json_encode( array(
			'jsonrpc' => '2.0',
			'id'      => $request_id,
			'method'  => 'initialize',
			'params'  => array(
				'protocolVersion' => '2025-03-26',
				'capabilities'    => new \stdClass(),
				'clientInfo'      => array(
					'name'    => 'rate-limit-burst-harness',
					'version' => '1.0.0',
				),
			),
		) );
	}
}
