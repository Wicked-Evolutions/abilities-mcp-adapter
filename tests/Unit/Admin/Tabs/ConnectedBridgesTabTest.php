<?php
/**
 * Tests for ConnectedBridgesTab — verifies the H.2.6 diagnostic seam shipped
 * in the Phase 2 placeholder.
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
		// Reset the filter registry between cases so a stub from one test
		// doesn't leak into the next.
		$GLOBALS['wp_test_filters'] = array();
	}

	public function test_diagnostic_filter_name_is_documented_contract(): void {
		// Phase 1 / Phase 3 will hook this exact name. If we ever need to
		// rename it, that is a coordinated breaking change.
		$this->assertSame(
			'mcp_adapter_bridges_authorization_header_status',
			ConnectedBridgesTab::DIAGNOSTIC_FILTER
		);
	}

	public function test_render_emits_unknown_state_when_no_listener(): void {
		$html = $this->capture_render();
		$this->assertStringContainsString( 'wp-mcp-adapter-status-dot--unknown', $html );
		// Falls back to the default operator-facing message.
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
			// Listener returns a state outside the locked vocabulary.
			return array( 'state' => 'panic', 'message' => 'should be ignored' );
		} );

		$html = $this->capture_render();
		$this->assertStringContainsString( 'wp-mcp-adapter-status-dot--unknown', $html );
	}

	public function test_placeholder_explicitly_marks_phase_3_content_as_pending(): void {
		$html = $this->capture_render();
		// The empty-state copy is the operator's signal that the tab content
		// is intentional Phase 2 scope, not a regression.
		$this->assertStringContainsString( 'No bridges yet', $html );
	}

	private function capture_render(): string {
		ob_start();
		ConnectedBridgesTab::render();
		return (string) ob_get_clean();
	}
}
