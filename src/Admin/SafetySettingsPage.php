<?php
/**
 * Legacy redirector for ?page=mcp-adapter-safety.
 *
 * The Settings → MCP Safety page was consolidated into Settings → Abilities
 * MCP Adapter → Safety (Phase 2 of the OAuth 2.1 sprint, issue #31). This
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

/**
 * Redirector for the legacy MCP Safety page slug.
 */
final class SafetySettingsPage {

	/** Legacy page slug — kept so callers that reference it still resolve. */
	public const PAGE_SLUG = 'mcp-adapter-safety';

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

		wp_safe_redirect(
			AdapterAdminPage::tab_url( AdapterAdminPage::TAB_SAFETY ),
			301
		);
		exit;
	}
}
