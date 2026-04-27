<?php
/**
 * Capture OAuth boundary events in a bounded ring buffer for the
 * Connected Bridges audit slice.
 *
 * The MCP adapter's boundary log is fire-and-forget — Phase 1 never shipped a
 * persistent storage backend. To render a useful "recent OAuth activity" view
 * without changing the boundary contract, this class subscribes to the
 * `mcp_adapter_boundary_event` action and stores OAuth events in a small
 * WP option (last 25 events). Bounded size keeps option payload < 4 KB.
 *
 * Tags are already sanitized by {@see BoundaryEventEmitter::sanitize()} —
 * we never see token values, scope strings, or hashes.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Admin\Bridges
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Admin\Bridges;

/**
 * Subscribe + read the OAuth audit slice.
 */
final class BoundaryAuditBuffer {

	/** WP option name. */
	public const OPTION = 'abilities_oauth_audit_buffer';

	/** Maximum entries retained (FIFO). */
	public const MAX_ENTRIES = 25;

	/** OAuth events we record. */
	private const RECORDED_EVENTS = array(
		'boundary.oauth_token_issued',
		'boundary.oauth_token_refreshed',
		'boundary.oauth_token_revoked',
		'boundary.oauth_authorization_granted',
		'boundary.oauth_authorization_auto_approved',
		'boundary.oauth_authorization_denied',
		'boundary.oauth_authorize_error',
		'boundary.oauth_invalid_token',
	);

	/** Register the action listener. Idempotent. */
	public static function register(): void {
		if ( function_exists( 'add_action' ) ) {
			add_action( 'mcp_adapter_boundary_event', array( self::class, 'capture' ), 100, 3 );
		}
	}

	/**
	 * Action callback. Filters to OAuth events, then appends to the ring buffer.
	 *
	 * @param string     $event       Boundary event name.
	 * @param array      $tags        Already-sanitized tags.
	 * @param float|null $duration_ms Unused.
	 */
	public static function capture( string $event, array $tags = array(), ?float $duration_ms = null ): void {
		if ( ! in_array( $event, self::RECORDED_EVENTS, true ) ) {
			return;
		}

		$buffer = self::read();

		$buffer[] = array(
			'time'       => time(),
			'event'      => $event,
			'client_id'  => isset( $tags['client_id'] ) && is_string( $tags['client_id'] ) ? $tags['client_id'] : '',
			'user_id'    => isset( $tags['user_id'] ) && is_numeric( $tags['user_id'] ) ? (int) $tags['user_id'] : 0,
			'reason'     => isset( $tags['reason'] ) && is_string( $tags['reason'] ) ? $tags['reason'] : '',
			'error_code' => isset( $tags['error_code'] ) && is_string( $tags['error_code'] ) ? $tags['error_code'] : '',
		);

		// Trim to MAX_ENTRIES — keep the most recent N.
		if ( count( $buffer ) > self::MAX_ENTRIES ) {
			$buffer = array_slice( $buffer, -self::MAX_ENTRIES );
		}

		update_option( self::OPTION, $buffer, false );
	}

	/**
	 * Read the audit buffer, newest first.
	 *
	 * @return array<int, array{time:int,event:string,client_id:string,user_id:int,reason:string,error_code:string}>
	 */
	public static function read(): array {
		$raw = get_option( self::OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		// Defensive — keep only entries with the expected keys.
		$out = array();
		foreach ( $raw as $entry ) {
			if ( ! is_array( $entry ) || ! isset( $entry['event'] ) ) {
				continue;
			}
			$out[] = array(
				'time'       => (int) ( $entry['time'] ?? 0 ),
				'event'      => (string) $entry['event'],
				'client_id'  => (string) ( $entry['client_id'] ?? '' ),
				'user_id'    => (int) ( $entry['user_id'] ?? 0 ),
				'reason'     => (string) ( $entry['reason'] ?? '' ),
				'error_code' => (string) ( $entry['error_code'] ?? '' ),
			);
		}
		return $out;
	}

	/** For tests. */
	public static function clear(): void {
		delete_option( self::OPTION );
	}
}
