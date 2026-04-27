<?php
/**
 * H-3: OAuthCleanup — daily cron scheduling and deletion criteria.
 *
 * Pre-fix: no cleanup cron existed. All four kl_oauth_* tables grew unbounded.
 * Combined with an open DCR endpoint and the per-blog rate limit weakness (H-4),
 * the SITE_CAP=1000 ceiling was reachable from one IP in <1 hour.
 *
 * After fix: a daily cron deletes stale records per the criteria below and
 * emits admin notices when any table exceeds 50,000 rows (ROW_ALERT_THRESHOLD).
 *
 * Deletion criteria:
 *   - auth codes:    used = 1 OR expires_at < NOW()
 *   - access tokens: revoked = 1 AND expires_at < NOW()
 *   - refresh tokens: revoked = 1 AND expires_at < NOW()
 *   - DCR clients:   revoked_at IS NOT NULL AND revoked_at < 30-day cutoff
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthCleanup;

final class OAuthCleanupTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		$this->original_wpdb        = $GLOBALS['wpdb'];
		$GLOBALS['wp_test_cron']    = array();
		$GLOBALS['wp_test_options'] = array();
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb']            = $this->original_wpdb;
		$GLOBALS['wp_test_cron']    = array();
		$GLOBALS['wp_test_options'] = array();
	}

	// -------------------------------------------------------------------------
	// Scheduling
	// -------------------------------------------------------------------------

	public function test_schedule_registers_cron_hook_when_not_scheduled(): void {
		// No cron entry → schedule() must register one.
		OAuthCleanup::schedule();
		$this->assertNotFalse(
			wp_next_scheduled( OAuthCleanup::CRON_HOOK ),
			'schedule() must register the cleanup cron hook'
		);
	}

	public function test_schedule_is_idempotent(): void {
		// Already scheduled → second call must not error or move timestamp.
		OAuthCleanup::schedule();
		$first = wp_next_scheduled( OAuthCleanup::CRON_HOOK );
		OAuthCleanup::schedule();
		$second = wp_next_scheduled( OAuthCleanup::CRON_HOOK );
		$this->assertSame( $first, $second, 'schedule() must be idempotent' );
	}

	public function test_unschedule_removes_cron_hook(): void {
		OAuthCleanup::schedule();
		$this->assertNotFalse( wp_next_scheduled( OAuthCleanup::CRON_HOOK ) );

		OAuthCleanup::unschedule();
		$this->assertFalse( wp_next_scheduled( OAuthCleanup::CRON_HOOK ) );
	}

	public function test_unschedule_on_missing_hook_does_not_throw(): void {
		// Already absent — must not error.
		OAuthCleanup::unschedule();
		$this->assertFalse( wp_next_scheduled( OAuthCleanup::CRON_HOOK ) );
	}

	public function test_cron_hook_name_is_abilities_oauth_cleanup_unused_clients(): void {
		$this->assertSame( 'abilities_oauth_cleanup_unused_clients', OAuthCleanup::CRON_HOOK );
	}

	// -------------------------------------------------------------------------
	// run() — deletion criteria (via query capture)
	// -------------------------------------------------------------------------

	/**
	 * Build a $wpdb stub that captures all DELETE queries and returns
	 * a count smaller than BATCH (so the loop exits after one pass).
	 */
	private function install_capturing_wpdb(): object {
		$capture        = new \stdClass();
		$capture->queries = array();

		$GLOBALS['wpdb'] = new class( $capture ) {
			public string $prefix = 'wp_';
			private object $capture;

			public function __construct( object $c ) { $this->capture = $c; }

			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )         { return null; }
			public function get_var( $q )         { return 0; } // row count = 0 → no alerts
			public function get_results( $q )     { return array(); }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null ) { return 1; }

			public function query( $sql ) {
				$this->capture->queries[] = $sql;
				// Return 0 so batch_delete loop exits after one iteration.
				return 0;
			}
		};

		return $capture;
	}

	public function test_run_issues_delete_for_used_or_expired_codes(): void {
		$capture = $this->install_capturing_wpdb();
		OAuthCleanup::run();

		$code_queries = array_filter( $capture->queries, fn( $q ) => str_contains( $q, 'kl_oauth_codes' ) );
		$this->assertNotEmpty( $code_queries, 'run() must issue DELETE for kl_oauth_codes' );

		$combined = implode( ' ', $code_queries );
		$this->assertStringContainsString( 'used = 1', $combined );
		$this->assertStringContainsString( 'expires_at', $combined );
	}

	public function test_run_issues_delete_for_revoked_and_expired_access_tokens(): void {
		$capture = $this->install_capturing_wpdb();
		OAuthCleanup::run();

		$token_queries = array_filter( $capture->queries, fn( $q ) => str_contains( $q, 'kl_oauth_tokens' ) );
		$this->assertNotEmpty( $token_queries, 'run() must issue DELETE for kl_oauth_tokens' );

		$combined = implode( ' ', $token_queries );
		$this->assertStringContainsString( 'revoked = 1', $combined );
		$this->assertStringContainsString( 'expires_at', $combined );
	}

	public function test_run_issues_delete_for_revoked_and_expired_refresh_tokens(): void {
		$capture = $this->install_capturing_wpdb();
		OAuthCleanup::run();

		$rt_queries = array_filter( $capture->queries, fn( $q ) => str_contains( $q, 'kl_oauth_refresh_tokens' ) );
		$this->assertNotEmpty( $rt_queries, 'run() must issue DELETE for kl_oauth_refresh_tokens' );

		$combined = implode( ' ', $rt_queries );
		$this->assertStringContainsString( 'revoked = 1', $combined );
		$this->assertStringContainsString( 'expires_at', $combined );
	}

	public function test_run_issues_delete_for_revoked_dcr_clients_past_ttl(): void {
		$capture = $this->install_capturing_wpdb();
		OAuthCleanup::run();

		$client_queries = array_filter( $capture->queries, fn( $q ) => str_contains( $q, 'kl_oauth_clients' ) );
		$this->assertNotEmpty( $client_queries, 'run() must issue DELETE for kl_oauth_clients' );

		$combined = implode( ' ', $client_queries );
		$this->assertStringContainsString( 'revoked_at', $combined );
	}

	public function test_run_uses_limit_in_batch_deletes(): void {
		$capture = $this->install_capturing_wpdb();
		OAuthCleanup::run();

		$delete_queries = array_filter( $capture->queries, fn( $q ) => str_starts_with( trim( $q ), 'DELETE' ) );
		foreach ( $delete_queries as $q ) {
			$this->assertStringContainsString( 'LIMIT', $q, 'Every DELETE must include a LIMIT clause' );
		}
	}

	// -------------------------------------------------------------------------
	// Row alert threshold
	// -------------------------------------------------------------------------

	public function test_row_alert_saved_as_option_when_threshold_exceeded(): void {
		$GLOBALS['wpdb'] = new class {
			public string $prefix = 'wp_';
			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )         { return null; }
			public function get_var( $q )         { return 60000; } // above threshold
			public function get_results( $q )     { return array(); }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null ) { return 1; }
			public function query( $sql )         { return 0; }
		};

		OAuthCleanup::run();

		$alert = get_option( 'abilities_oauth_row_alert' );
		$this->assertNotFalse( $alert, 'Row alert option must be set when threshold exceeded' );
		$this->assertStringContainsString( '60', (string) $alert );
	}

	public function test_row_alert_not_set_when_below_threshold(): void {
		$capture = $this->install_capturing_wpdb();

		OAuthCleanup::run();

		// get_var returns 0, so no alert should be written.
		$alert = get_option( 'abilities_oauth_row_alert', '' );
		$this->assertSame( '', $alert );
	}

	public function test_alert_threshold_constant_is_50000(): void {
		$this->assertSame( 50000, OAuthCleanup::ROW_ALERT_THRESHOLD );
	}
}
