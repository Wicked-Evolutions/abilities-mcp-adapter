<?php
/**
 * Legacy redirector for ?page=mcp-adapter-abilities.
 *
 * The Settings → MCP Abilities page was consolidated into Settings → Abilities
 * MCP Adapter → Abilities (Phase 2 of the OAuth 2.1 sprint, issue #31). This
 * class no longer registers a menu entry. It only intercepts the legacy URL
 * and 301-redirects to the new tab so existing bookmarks keep working.
 *
 * The PAGE_SLUG constant is kept so any external callers (or stored options
 * referencing the slug) continue to resolve.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Admin;

use WickedEvolutions\McpAdapter\Admin\Tabs\AbilitiesTab;

/**
 * Redirector for the legacy MCP Abilities page slug.
 */
final class AbilitySettingsPage {

	/** Legacy page slug — kept so callers that reference it still resolve. */
	public const PAGE_SLUG = 'mcp-adapter-abilities';

	/**
	 * Hook the redirect on admin_init.
	 */
	public static function register(): void {
		add_action( 'admin_init', array( self::class, 'maybe_redirect' ) );
	}

	/**
	 * Issue a 301 to the consolidated tab when the legacy URL is requested.
	 *
	 * Read-only check on $_GET['page'] — no nonce required.
	 */
	public static function maybe_redirect(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only URL match.
		if ( ! isset( $_GET['page'] ) || self::PAGE_SLUG !== $_GET['page'] ) {
			return;
		}

		$args = array();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only URL match.
		if ( isset( $_GET['tab'] ) && 'license' === sanitize_key( wp_unslash( (string) $_GET['tab'] ) ) ) {
			$args['subtab'] = AbilitiesTab::SUBTAB_LICENSE;
		}

		wp_safe_redirect(
			AdapterAdminPage::tab_url( AdapterAdminPage::TAB_ABILITIES, $args ),
			301
		);
		exit;
	}
}
