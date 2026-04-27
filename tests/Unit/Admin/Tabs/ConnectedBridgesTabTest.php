<?php
/**
 * Tests for ConnectedBridgesTab — Phase 3 content + the H.2.6 diagnostic seam.
 *
 * Verifies:
 *   - The empty-state copy when no clients are registered.
 *   - The H.2.6 diagnostic seam (filter contract preserved from Phase 2).
 *   - The bridges table renders columns + warning icon + revoke form.
 *   - The revoke handler verifies nonce + capability + cascades through ClientRegistry::revoke().
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Admin\Tabs;

use WickedEvolutions\McpAdapter\Admin\Tabs\ConnectedBridgesTab;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class ConnectedBridgesTabTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		$GLOBALS['wp_test_filters']  = array();
		$GLOBALS['wp_test_options']  = array();
		$GLOBALS['wp_test_users']    = array();
		// Default: empty client list. Tests can override $wpdb to seed rows.
		$GLOBALS['wpdb'] = new class {
			public string $prefix = 'wp_';
			public function get_results( $query ) { return array(); }
			public function get_row( $query ) { return null; }
			public function get_var( $query ) { return null; }
			public function prepare( $query, ...$args ) { return $query; }
			public function insert( $table, $data, $format = null ) { return 1; }
			public function update( $table, $data, $where, $format = null, $where_format = null ) { return 1; }
			public function query( $sql ) { return true; }
		};
	}

	// ─── Diagnostic seam (Phase 2 contract, must remain intact) ─────────────────

	public function test_diagnostic_filter_name_is_documented_contract(): void {
		$this->assertSame(
			'mcp_adapter_bridges_authorization_header_status',
			ConnectedBridgesTab::DIAGNOSTIC_FILTER
		);
	}

	public function test_render_emits_unknown_state_when_no_listener(): void {
		$html = $this->capture_render();
		$this->assertStringContainsString( 'wp-mcp-adapter-status-dot--unknown', $html );
		$this->assertStringContainsString( 'has not reported yet', $html );
	}

	public function test_render_uses_listener_status_when_filter_returns_ok(): void {
		add_filter( ConnectedBridgesTab::DIAGNOSTIC_FILTER, function () {
			return array(
				'state'    => 'ok',
				'message'  => 'Detected on last 100 requests.',
				'docs_url' => 'https://example.com/setup',
			);
		} );
		$html = $this->capture_render();
		$this->assertStringContainsString( 'wp-mcp-adapter-status-dot--ok', $html );
		$this->assertStringContainsString( 'Detected on last 100 requests.', $html );
		$this->assertStringContainsString( 'https://example.com/setup', $html );
	}

	public function test_render_uses_warn_when_header_missing(): void {
		add_filter( ConnectedBridgesTab::DIAGNOSTIC_FILTER, function () {
			return array(
				'state'   => 'warn',
				'message' => 'No Authorization header detected on last 100 requests.',
			);
		} );
		$html = $this->capture_render();
		$this->assertStringContainsString( 'wp-mcp-adapter-status-dot--warn', $html );
		$this->assertStringContainsString( 'No Authorization header detected', $html );
	}

	public function test_unknown_state_value_collapses_to_unknown(): void {
		add_filter( ConnectedBridgesTab::DIAGNOSTIC_FILTER, function () {
			return array( 'state' => 'panic', 'message' => 'should be ignored' );
		} );
		$html = $this->capture_render();
		$this->assertStringContainsString( 'wp-mcp-adapter-status-dot--unknown', $html );
	}

	// ─── Empty + table render ────────────────────────────────────────────────────

	public function test_empty_state_shows_helpful_copy(): void {
		$html = $this->capture_render();
		// Phase 3 copy — operator-facing message.
		$this->assertStringContainsString( 'No bridges have completed', $html );
		$this->assertStringContainsString( 'No bridges yet', $html );
	}

	public function test_table_renders_with_seeded_clients(): void {
		$clients = array(
			(object) array(
				'client_id'        => 'cid-table-1',
				'client_name'      => 'Test Bridge One',
				'software_id'      => 'com.example.bridge',
				'software_version' => '1.0.0',
				'scopes'           => 'abilities:read',
				'registered_ip'    => '127.0.0.1',
				'registered_at'    => '2026-04-01 12:00:00',
			),
		);
		$this->seed_client_list( $clients );

		$html = $this->capture_render();
		$this->assertStringContainsString( 'Test Bridge One', $html );
		$this->assertStringContainsString( 'Authorized bridges', $html );
		$this->assertStringContainsString( 'wp-mcp-bridges-table', $html );
		// Revoke form rendered with client_id.
		$this->assertStringContainsString( 'cid-table-1', $html );
		$this->assertStringContainsString( 'mcp_bridges_action', $html );
	}

	// ─── Revoke handler ──────────────────────────────────────────────────────────

	public function test_handle_action_does_nothing_without_capability(): void {
		$GLOBALS['wp_test_caps'] = array();
		$_POST = array(
			ConnectedBridgesTab::ACTION_FIELD => ConnectedBridgesTab::ACTION_REVOKE,
			ConnectedBridgesTab::NONCE_FIELD  => 'test-nonce',
			'client_id'                       => 'cid-x',
		);
		$revoke_calls = $this->spy_revokes();
		ConnectedBridgesTab::handle_action();
		$this->assertSame( 0, $revoke_calls() );
	}

	public function test_handle_action_does_nothing_without_valid_nonce(): void {
		$GLOBALS['wp_test_caps'] = array( 'manage_options' => true );
		$_POST = array(
			ConnectedBridgesTab::ACTION_FIELD => ConnectedBridgesTab::ACTION_REVOKE,
			ConnectedBridgesTab::NONCE_FIELD  => 'wrong-nonce',
			'client_id'                       => 'cid-x',
		);
		$revoke_calls = $this->spy_revokes();
		ConnectedBridgesTab::handle_action();
		$this->assertSame( 0, $revoke_calls() );
	}

	public function test_handle_action_revokes_when_nonce_and_capability_present(): void {
		$GLOBALS['wp_test_caps'] = array( 'manage_options' => true );
		$_POST = array(
			ConnectedBridgesTab::ACTION_FIELD => ConnectedBridgesTab::ACTION_REVOKE,
			ConnectedBridgesTab::NONCE_FIELD  => 'test-nonce',
			'client_id'                       => 'cid-revoke',
		);
		$revoke_calls = $this->spy_revokes();
		try {
			ConnectedBridgesTab::handle_action();
		} catch ( \WickedEvolutions\McpAdapter\Tests\RedirectException $e ) {
			// Redirect is expected on success — caught by the test stub.
		}
		$this->assertSame( 1, $revoke_calls() );
	}

	// ─── Helpers ────────────────────────────────────────────────────────────────

	/** Capture render output. */
	private function capture_render(): string {
		ob_start();
		ConnectedBridgesTab::render();
		return (string) ob_get_clean();
	}

	/** Seed a client list. Called once per test that wants a populated table. */
	private function seed_client_list( array $clients ): void {
		$GLOBALS['wpdb'] = new class( $clients ) {
			public string $prefix = 'wp_';
			private array $clients;
			public function __construct( array $clients ) { $this->clients = $clients; }
			public function get_results( $query ) {
				return str_contains( (string) $query, 'kl_oauth_clients' ) ? $this->clients : array();
			}
			public function get_row( $query ) { return null; }
			public function get_var( $query ) { return null; }
			public function prepare( $query, ...$args ) { return $query; }
			public function insert( $table, $data, $format = null ) { return 1; }
			public function update( $table, $data, $where, $format = null, $where_format = null ) { return 1; }
			public function query( $sql ) { return true; }
		};
	}

	/**
	 * Replace the $wpdb->update() implementation with a counter so we can
	 * detect that ClientRegistry::revoke()'s cascade transaction ran.
	 *
	 * @return callable(): int Returns the number of UPDATE statements observed.
	 */
	private function spy_revokes(): callable {
		$counter = new \stdClass();
		$counter->n = 0;
		$GLOBALS['wpdb'] = new class( $counter ) {
			public string $prefix = 'wp_';
			private \stdClass $c;
			public function __construct( \stdClass $c ) { $this->c = $c; }
			public function get_results( $query ) { return array(); }
			public function get_row( $query ) { return null; }
			public function get_var( $query ) { return null; }
			public function prepare( $query, ...$args ) { return $query; }
			public function insert( $table, $data, $format = null ) { return 1; }
			public function update( $table, $data, $where, $format = null, $where_format = null ) {
				if ( str_contains( (string) $table, 'kl_oauth_clients' ) ) {
					$this->c->n++;
				}
				return 1;
			}
			public function query( $sql ) { return true; }
		};
		return static fn() => $counter->n;
	}
}
