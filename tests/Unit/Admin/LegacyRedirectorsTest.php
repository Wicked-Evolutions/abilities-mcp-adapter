<?php
/**
 * Tests for the legacy AbilitySettingsPage / SafetySettingsPage classes.
 *
 * After Phase 2 these classes no longer render anything — they only watch
 * for their old ?page slug and 301-redirect to the consolidated tab. The
 * acceptance criterion in #31 says "Old URLs redirect"; these tests lock
 * that contract.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Admin;

use WickedEvolutions\McpAdapter\Admin\AbilitySettingsPage;
use WickedEvolutions\McpAdapter\Admin\AdapterAdminPage;
use WickedEvolutions\McpAdapter\Admin\SafetySettingsPage;
use WickedEvolutions\McpAdapter\Tests\RedirectException;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class LegacyRedirectorsTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		$_GET                                  = array();
		$GLOBALS['wp_test_redirect']           = null;
		$GLOBALS['wp_test_is_network_admin']   = false;
		$GLOBALS['wp_test_admin_url']          = 'https://example.com/wp-admin/';
		$GLOBALS['wp_test_network_admin_url']  = 'https://example.com/wp-admin/network/';
	}

	public function test_legacy_slugs_are_preserved_for_external_callers(): void {
		// Stored options + bookmarks reference these literal strings; they
		// must not change when the URL is consolidated.
		$this->assertSame( 'mcp-adapter-abilities', AbilitySettingsPage::PAGE_SLUG );
		$this->assertSame( 'mcp-adapter-safety',    SafetySettingsPage::PAGE_SLUG );
	}

	public function test_abilities_redirector_ignores_unrelated_pages(): void {
		$_GET = array( 'page' => 'something-else' );
		AbilitySettingsPage::maybe_redirect();
		$this->assertNull( $GLOBALS['wp_test_redirect'] );
	}

	public function test_abilities_redirector_emits_301_to_new_tab(): void {
		$_GET = array( 'page' => AbilitySettingsPage::PAGE_SLUG );
		try {
			AbilitySettingsPage::maybe_redirect();
			$this->fail( 'Expected RedirectException.' );
		} catch ( RedirectException $e ) {
			// Expected.
		}

		$this->assertNotNull( $GLOBALS['wp_test_redirect'] );
		$this->assertSame( 301, $GLOBALS['wp_test_redirect']['status'] );
		$this->assertStringContainsString( 'page=mcp-adapter', $GLOBALS['wp_test_redirect']['location'] );
		$this->assertStringContainsString( 'tab=' . AdapterAdminPage::TAB_ABILITIES, $GLOBALS['wp_test_redirect']['location'] );
	}

	public function test_abilities_redirector_carries_license_subtab_through(): void {
		// Old URL: ?page=mcp-adapter-abilities&tab=license → land on the
		// new license sub-tab, not the default abilities sub-tab.
		$_GET = array(
			'page' => AbilitySettingsPage::PAGE_SLUG,
			'tab'  => 'license',
		);
		try {
			AbilitySettingsPage::maybe_redirect();
			$this->fail( 'Expected RedirectException.' );
		} catch ( RedirectException $e ) {
			// Expected.
		}

		$location = $GLOBALS['wp_test_redirect']['location'];
		$this->assertStringContainsString( 'subtab=license', $location );
	}

	public function test_safety_redirector_ignores_unrelated_pages(): void {
		$_GET = array( 'page' => 'something-else' );
		SafetySettingsPage::maybe_redirect();
		$this->assertNull( $GLOBALS['wp_test_redirect'] );
	}

	public function test_safety_redirector_emits_301_to_new_tab(): void {
		$_GET = array( 'page' => SafetySettingsPage::PAGE_SLUG );
		try {
			SafetySettingsPage::maybe_redirect();
			$this->fail( 'Expected RedirectException.' );
		} catch ( RedirectException $e ) {
			// Expected.
		}

		$this->assertNotNull( $GLOBALS['wp_test_redirect'] );
		$this->assertSame( 301, $GLOBALS['wp_test_redirect']['status'] );
		$this->assertStringContainsString( 'tab=' . AdapterAdminPage::TAB_SAFETY, $GLOBALS['wp_test_redirect']['location'] );
	}
}
