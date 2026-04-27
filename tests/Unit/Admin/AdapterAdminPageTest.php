<?php
/**
 * Tests for AdapterAdminPage — the consolidated tab shell shipped in Phase 2.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Admin;

use WickedEvolutions\McpAdapter\Admin\AdapterAdminPage;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class AdapterAdminPageTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		$_GET                              = array();
		$GLOBALS['wp_test_is_network_admin'] = false;
		$GLOBALS['wp_test_admin_url']      = 'https://example.com/wp-admin/';
		$GLOBALS['wp_test_network_admin_url'] = 'https://example.com/wp-admin/network/';
		$GLOBALS['wp_test_menu_pages']     = array();
	}

	public function test_tab_ids_lists_all_three_phase_2_tabs(): void {
		$this->assertSame(
			array( 'abilities', 'safety', 'bridges' ),
			AdapterAdminPage::tab_ids()
		);
	}

	public function test_default_tab_is_abilities(): void {
		$this->assertSame( 'abilities', AdapterAdminPage::DEFAULT_TAB );
		$this->assertSame( 'abilities', AdapterAdminPage::active_tab() );
	}

	public function test_active_tab_resolves_known_tabs(): void {
		foreach ( AdapterAdminPage::tab_ids() as $tab ) {
			$_GET = array( 'tab' => $tab );
			$this->assertSame( $tab, AdapterAdminPage::active_tab() );
		}
	}

	public function test_active_tab_falls_back_when_unknown(): void {
		$_GET = array( 'tab' => 'no-such-tab' );
		$this->assertSame( AdapterAdminPage::DEFAULT_TAB, AdapterAdminPage::active_tab() );
	}

	public function test_page_url_targets_top_level_admin_php(): void {
		$url = AdapterAdminPage::page_url();
		$this->assertStringContainsString( 'wp-admin/admin.php', $url );
		$this->assertStringContainsString( 'page=mcp-adapter', $url );
	}

	public function test_tab_url_appends_tab_query_arg(): void {
		$url = AdapterAdminPage::tab_url( AdapterAdminPage::TAB_SAFETY );
		$this->assertStringContainsString( 'page=mcp-adapter', $url );
		$this->assertStringContainsString( 'tab=safety', $url );
	}

	public function test_tab_url_preserves_extra_args(): void {
		$url = AdapterAdminPage::tab_url(
			AdapterAdminPage::TAB_ABILITIES,
			array( 'subtab' => 'license', 'updated' => '1' )
		);
		$this->assertStringContainsString( 'tab=abilities', $url );
		$this->assertStringContainsString( 'subtab=license', $url );
		$this->assertStringContainsString( 'updated=1', $url );
	}

	public function test_page_url_uses_network_admin_in_network_context(): void {
		$GLOBALS['wp_test_is_network_admin'] = true;
		$url                                 = AdapterAdminPage::page_url();
		$this->assertStringContainsString( 'wp-admin/network/admin.php', $url );
	}

	public function test_add_menu_page_registers_top_level_entry(): void {
		AdapterAdminPage::add_menu_page();
		$this->assertCount( 1, $GLOBALS['wp_test_menu_pages'] );
		$entry = $GLOBALS['wp_test_menu_pages'][0];
		$this->assertSame( AdapterAdminPage::PAGE_SLUG, $entry['menu_slug'] );
		$this->assertSame( 'manage_options', $entry['capability'] );
		$this->assertSame( 'dashicons-rest-api', $entry['icon'] );
	}

	public function test_add_menu_page_uses_network_capability_in_network_admin(): void {
		$GLOBALS['wp_test_is_network_admin'] = true;
		AdapterAdminPage::add_menu_page();
		$entry = $GLOBALS['wp_test_menu_pages'][0];
		$this->assertSame( 'manage_network_options', $entry['capability'] );
	}

	public function test_tab_constants_match_documented_ids(): void {
		// The bridges/safety/abilities ids are stable contracts — Phase 3
		// hooks rely on them. Lock them down.
		$this->assertSame( 'abilities', AdapterAdminPage::TAB_ABILITIES );
		$this->assertSame( 'safety',    AdapterAdminPage::TAB_SAFETY );
		$this->assertSame( 'bridges',   AdapterAdminPage::TAB_BRIDGES );
		$this->assertSame( 'mcp-adapter', AdapterAdminPage::PAGE_SLUG );
	}
}
