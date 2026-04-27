<?php
/**
 * Populate the H.2.6 Authorization-header diagnostic from a rolling counter
 * of recent MCP requests.
 *
 * The Phase 2 placeholder shipped an extension hook
 * (`mcp_adapter_bridges_authorization_header_status`) but no data source.
 * Phase 3 provides a minimal data source that doesn't require new tables:
 *   - On every MCP REST request, the bearer auth path notes whether the
 *     Authorization header was present.
 *   - The probe accumulates a small rolling counter (last 100 requests).
 *   - The diagnostic filter returns the operator-facing status from this
 *     counter.
 *
 * Hosting setup docs link is the same one the design doc references for
 * the operator setup guide.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Admin\Bridges
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Admin\Bridges;

use WickedEvolutions\McpAdapter\Admin\Tabs\ConnectedBridgesTab;

/**
 * Rolling Authorization-header presence counter + diagnostic resolver.
 */
final class AuthHeaderProbe {

	/** WP option storing the rolling counter. */
	public const OPTION = 'abilities_oauth_auth_header_probe';

	/** Window size — last N MCP requests considered. */
	public const WINDOW_SIZE = 100;

	/** Hosting docs link surfaced to the operator. */
	public const DOCS_URL = 'https://wickedevolutions.com/docs/abilities-mcp/oauth#authorization-header';

	/** Register hook + filter. Idempotent. */
	public static function register(): void {
		if ( function_exists( 'add_filter' ) ) {
			add_filter( ConnectedBridgesTab::DIAGNOSTIC_FILTER, array( self::class, 'resolve_status' ) );
		}
	}

	/**
	 * Record one observation.
	 *
	 * @param bool $header_present Whether the request's Authorization header was readable.
	 */
	public static function record( bool $header_present ): void {
		$state = self::read_state();

		$state['observations'][] = $header_present ? 1 : 0;
		if ( count( $state['observations'] ) > self::WINDOW_SIZE ) {
			$state['observations'] = array_slice( $state['observations'], -self::WINDOW_SIZE );
		}
		$state['last_seen_unix'] = time();

		update_option( self::OPTION, $state, false );
	}

	/**
	 * Filter callback returning the diagnostic shape Phase 2 expects.
	 *
	 * Returning `null` lets the placeholder fall back to its own "unknown"
	 * default. Returning an array with `state` set to ok/warn/unknown
	 * overrides the default.
	 *
	 * @param mixed $existing Previously-filtered value.
	 * @return mixed
	 */
	public static function resolve_status( $existing = null ) {
		$state = self::read_state();
		$obs   = $state['observations'];

		if ( empty( $obs ) ) {
			// No requests yet — let the placeholder's "unknown" copy stand.
			return $existing;
		}

		$present = array_sum( $obs );
		$total   = count( $obs );
		$missing = $total - $present;

		if ( 0 === $present ) {
			return array(
				'state'    => 'warn',
				'message'  => sprintf(
					/* translators: 1: count of recent requests */
					__( 'No Authorization header detected on the last %1$d MCP request(s). Your hosting may be stripping it before PHP sees it.', 'mcp-adapter' ),
					$total
				),
				'docs_url' => self::DOCS_URL,
			);
		}

		if ( $missing > 0 ) {
			return array(
				'state'    => 'warn',
				'message'  => sprintf(
					/* translators: 1: present count, 2: total count */
					__( 'Authorization header detected on %1$d of the last %2$d MCP requests. Missing on the rest — your hosting may be stripping it intermittently.', 'mcp-adapter' ),
					$present,
					$total
				),
				'docs_url' => self::DOCS_URL,
			);
		}

		return array(
			'state'    => 'ok',
			'message'  => sprintf(
				/* translators: 1: count of recent requests */
				__( 'Authorization header detected on the last %1$d MCP request(s).', 'mcp-adapter' ),
				$total
			),
			'docs_url' => '',
		);
	}

	/**
	 * @return array{observations:int[], last_seen_unix:int}
	 */
	private static function read_state(): array {
		$raw = get_option( self::OPTION, array() );
		$obs = is_array( $raw['observations'] ?? null ) ? $raw['observations'] : array();
		$obs = array_values( array_map( static fn( $v ) => (int) $v ? 1 : 0, $obs ) );
		return array(
			'observations'   => $obs,
			'last_seen_unix' => (int) ( $raw['last_seen_unix'] ?? 0 ),
		);
	}

	/** For tests. */
	public static function clear(): void {
		delete_option( self::OPTION );
	}
}
