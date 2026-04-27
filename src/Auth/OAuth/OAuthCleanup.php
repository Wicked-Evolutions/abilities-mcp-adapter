<?php
/**
 * Daily OAuth table cleanup cron (H.3.3).
 *
 * Deletes stale records from all four kl_oauth_* tables to prevent unbounded
 * growth. Runs in batches (BATCH = 500) to avoid long-running queries on large
 * installs. Emits admin notices when any table exceeds the 50,000-row absolute
 * cap, alerting operators before DCR is force-disabled.
 *
 * Schedule management lives in the main plugin file:
 *   - register_activation_hook  → OAuthCleanup::schedule()
 *   - register_deactivation_hook → OAuthCleanup::unschedule()
 *   - cron_schedules filter      → adds 'abilities_mcp_daily' interval
 *   - CRON_HOOK action           → OAuthCleanup::run()
 *
 * Deletion criteria:
 *   - auth codes:       used = 1 OR expires_at < NOW()
 *   - access tokens:    revoked = 1 AND expires_at < NOW()
 *   - refresh tokens:   revoked = 1 AND expires_at < NOW()
 *   - DCR clients:      revoked_at IS NOT NULL AND revoked_at < NOW() - CLIENT_TTL_DAYS
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

/**
 * Manages daily OAuth table cleanup.
 */
final class OAuthCleanup {

	/** WP-Cron hook name. */
	public const CRON_HOOK = 'abilities_oauth_cleanup_unused_clients';

	/** WP-Cron schedule name. */
	public const SCHEDULE = 'abilities_mcp_daily';

	/** Batch size for DELETE loops — avoids long-query timeouts. */
	private const BATCH = 500;

	/**
	 * Rows above this threshold trigger an admin notice (H.3.3).
	 * Applies per-table, not total.
	 */
	public const ROW_ALERT_THRESHOLD = 50000;

	/**
	 * Revoked client records are purged after this many days.
	 * Keeps a short audit trail without growing unbounded.
	 */
	private const CLIENT_TTL_DAYS = 30;

	/**
	 * Schedule the cleanup cron if not already scheduled.
	 * Call from register_activation_hook and from the init hook after plugin updates.
	 */
	public static function schedule(): void {
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_schedule_event' ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, self::SCHEDULE, self::CRON_HOOK );
		}
	}

	/**
	 * Unschedule the cleanup cron. Call from register_deactivation_hook.
	 */
	public static function unschedule(): void {
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_unschedule_event' ) ) {
			return;
		}
		$timestamp = wp_next_scheduled( self::CRON_HOOK );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, self::CRON_HOOK );
		}
	}

	/**
	 * Main cleanup entry point. Bound to the CRON_HOOK action.
	 *
	 * Deletes stale records in batches, then checks row counts against the
	 * alert threshold.
	 */
	public static function run(): void {
		global $wpdb;

		$p   = $wpdb->prefix;
		$now = gmdate( 'Y-m-d H:i:s' );

		// Delete used or expired authorization codes.
		self::batch_delete(
			"{$p}kl_oauth_codes",
			"used = 1 OR expires_at < '$now'"
		);

		// Delete revoked-and-expired access tokens.
		self::batch_delete(
			"{$p}kl_oauth_tokens",
			"revoked = 1 AND expires_at < '$now'"
		);

		// Delete revoked-and-expired refresh tokens.
		self::batch_delete(
			"{$p}kl_oauth_refresh_tokens",
			"revoked = 1 AND expires_at < '$now'"
		);

		// Delete revoked DCR clients past their audit retention window.
		$client_cutoff = gmdate( 'Y-m-d H:i:s', time() - ( self::CLIENT_TTL_DAYS * DAY_IN_SECONDS ) );
		self::batch_delete(
			"{$p}kl_oauth_clients",
			"revoked_at IS NOT NULL AND revoked_at < '$client_cutoff'"
		);

		// Alert if any table is approaching the absolute cap.
		self::maybe_alert_row_counts( $p );
	}

	/**
	 * Delete rows matching $where_clause in BATCH-sized loops until none remain.
	 *
	 * @param string $table       Full table name (with prefix).
	 * @param string $where_clause Raw SQL WHERE clause (no user input — all values interpolated above).
	 */
	private static function batch_delete( string $table, string $where_clause ): void {
		global $wpdb;

		do {
			$deleted = $wpdb->query(
				"DELETE FROM `{$table}` WHERE {$where_clause} LIMIT " . self::BATCH
			);
		} while ( $deleted === self::BATCH );
	}

	/**
	 * Check row counts for all four tables. If any exceeds ROW_ALERT_THRESHOLD,
	 * emit an admin notice via the admin_notices hook.
	 *
	 * @param string $p Table prefix.
	 */
	private static function maybe_alert_row_counts( string $p ): void {
		global $wpdb;

		$tables = [
			"{$p}kl_oauth_clients"        => 'OAuth Clients',
			"{$p}kl_oauth_codes"          => 'OAuth Codes',
			"{$p}kl_oauth_tokens"         => 'OAuth Access Tokens',
			"{$p}kl_oauth_refresh_tokens" => 'OAuth Refresh Tokens',
		];

		$alerts = [];
		foreach ( $tables as $table => $label ) {
			$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$table}`" );
			if ( $count >= self::ROW_ALERT_THRESHOLD ) {
				$alerts[] = sprintf( '%s: %s rows', $label, number_format( $count ) );
			}
		}

		if ( empty( $alerts ) ) {
			return;
		}

		$message = implode( ', ', $alerts );
		update_option( 'abilities_oauth_row_alert', $message );

		add_action( 'admin_notices', static function () use ( $message ) {
			echo '<div class="notice notice-warning"><p><strong>Abilities MCP Adapter:</strong> '
				. esc_html( 'OAuth table row count alert: ' . $message )
				. '</p></div>';
		} );
	}
}
