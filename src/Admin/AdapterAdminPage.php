<?php
/**
 * Top-level admin page coordinator for the MCP Adapter.
 *
 * Mirrors the structure of `abilities-for-ai/admin/dashboard.php` (the canonical
 * design language locked in DESIGN — OAuth 2.1, Appendix B). Registers the
 * top-level menu, dispatches form submissions to the active tab, and renders
 * the tab navigation + active tab body.
 *
 * Tabs:
 *   - abilities — migrated from AbilitySettingsPage (per-ability enable + license)
 *   - safety    — migrated from SafetySettingsPage (master toggle, redaction, exemptions, trusted proxy)
 *   - bridges   — Connected Bridges placeholder shell (content in Phase 3)
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Admin;

use WickedEvolutions\McpAdapter\Admin\Tabs\AbilitiesTab;
use WickedEvolutions\McpAdapter\Admin\Tabs\ConnectedBridgesTab;
use WickedEvolutions\McpAdapter\Admin\Tabs\SafetyTab;

/**
 * Consolidated MCP Adapter admin page.
 */
final class AdapterAdminPage {

	/** Top-level menu slug. */
	public const PAGE_SLUG = 'mcp-adapter';

	/** Tab identifiers. */
	public const TAB_ABILITIES = 'abilities';
	public const TAB_SAFETY    = 'safety';
	public const TAB_BRIDGES   = 'bridges';

	/** Default tab when ?tab=… is absent. */
	public const DEFAULT_TAB = self::TAB_ABILITIES;

	/** Style handle for assets/admin.css. */
	public const STYLE_HANDLE = 'mcp-adapter-admin';

	/**
	 * Register the menu, form handlers, and asset enqueue.
	 */
	public static function register(): void {
		add_action( 'admin_menu',         array( self::class, 'add_menu_page' ) );
		add_action( 'network_admin_menu', array( self::class, 'add_menu_page' ) );
		add_action( 'admin_init',         array( self::class, 'dispatch_form_submissions' ) );
		add_action( 'admin_enqueue_scripts', array( self::class, 'enqueue_assets' ) );
	}

	/**
	 * Register the top-level menu entry.
	 *
	 * Same icon + capability as Abilities for AI's dashboard menu, so the
	 * two plugins sit side-by-side in the admin sidebar.
	 */
	public static function add_menu_page(): void {
		$capability = is_network_admin() ? 'manage_network_options' : 'manage_options';
		add_menu_page(
			__( 'Abilities MCP Adapter', 'mcp-adapter' ),
			__( 'MCP Adapter', 'mcp-adapter' ),
			$capability,
			self::PAGE_SLUG,
			array( self::class, 'render_page' ),
			'dashicons-rest-api',
			81
		);
	}

	/**
	 * Build the canonical URL for the consolidated page.
	 *
	 * @param array<string,scalar> $args Extra query args (typically tab/subtab/flash).
	 */
	public static function page_url( array $args = array() ): string {
		$args['page'] = self::PAGE_SLUG;
		$base         = is_network_admin() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' );
		return add_query_arg( $args, $base );
	}

	/**
	 * Build the URL for a specific tab (and optional sub-tab / flash args).
	 *
	 * @param string               $tab  One of the TAB_* constants.
	 * @param array<string,scalar> $args Extra query args.
	 */
	public static function tab_url( string $tab, array $args = array() ): string {
		$args['tab'] = $tab;
		return self::page_url( $args );
	}

	/**
	 * Resolve the active tab from $_GET, falling back to DEFAULT_TAB.
	 */
	public static function active_tab(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only tab switch.
		$requested = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( (string) $_GET['tab'] ) ) : '';
		return in_array( $requested, self::tab_ids(), true ) ? $requested : self::DEFAULT_TAB;
	}

	/**
	 * @return string[] Ordered list of tab ids.
	 */
	public static function tab_ids(): array {
		return array(
			self::TAB_ABILITIES,
			self::TAB_SAFETY,
			self::TAB_BRIDGES,
		);
	}

	/**
	 * Forward POST submissions to the appropriate tab handler.
	 *
	 * Each tab owns its own nonce + action multiplexing. We dispatch by which
	 * hidden marker the form posted, so a request to `?page=mcp-adapter&tab=safety`
	 * with a Safety form does not accidentally invoke the Abilities save path.
	 */
	public static function dispatch_form_submissions(): void {
		// Abilities tab: per-ability checkbox save.
		if ( isset( $_POST['mcp_adapter_abilities_nonce'] ) ) {
			AbilitiesTab::handle_save_abilities();
		}

		// Abilities tab: license activate/deactivate.
		if ( isset( $_POST['mcp_adapter_license_activate'] ) || isset( $_POST['mcp_adapter_license_deactivate'] ) ) {
			AbilitiesTab::handle_license_actions();
		}

		// Safety tab: any of the 8 multiplexed actions.
		if ( isset( $_POST['mcp_safety_action'] ) ) {
			SafetyTab::handle_save();
		}
	}

	/**
	 * Enqueue the shared stylesheet — only on this page.
	 *
	 * @param string $hook_suffix WP-supplied hook suffix for the current admin screen.
	 */
	public static function enqueue_assets( $hook_suffix ): void {
		if ( ! is_string( $hook_suffix ) || false === strpos( $hook_suffix, self::PAGE_SLUG ) ) {
			return;
		}
		$rel = 'assets/admin.css';
		$ver = defined( 'ABILITIES_MCP_ADAPTER_VERSION' ) ? ABILITIES_MCP_ADAPTER_VERSION : false;
		$url = function_exists( 'plugins_url' ) && defined( 'ABILITIES_MCP_ADAPTER_PATH' )
			? plugins_url( $rel, ABILITIES_MCP_ADAPTER_PATH . 'abilities-mcp-adapter.php' )
			: '';
		if ( '' === $url ) {
			return;
		}
		wp_enqueue_style( self::STYLE_HANDLE, $url, array(), $ver );
	}

	/**
	 * Render the consolidated page (header + tab nav + active tab body).
	 */
	public static function render_page(): void {
		$capability = is_network_admin() ? 'manage_network_options' : 'manage_options';
		if ( ! current_user_can( $capability ) ) {
			return;
		}

		$active_tab = self::active_tab();
		$version    = defined( 'ABILITIES_MCP_ADAPTER_VERSION' ) ? ABILITIES_MCP_ADAPTER_VERSION : '';

		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Abilities MCP Adapter', 'mcp-adapter' ); ?></h1>
			<p class="wp-mcp-adapter-subtitle">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: plugin version */
						__( 'v%s — connector for WordPress abilities over MCP', 'mcp-adapter' ),
						$version
					)
				);
				?>
			</p>

			<?php settings_errors( 'mcp_adapter_license' ); ?>

			<nav class="nav-tab-wrapper wp-mcp-adapter-tabs">
				<?php foreach ( self::tab_definitions() as $id => $label ) : ?>
					<a href="<?php echo esc_url( self::tab_url( $id ) ); ?>"
					   class="nav-tab <?php echo $id === $active_tab ? 'nav-tab-active' : ''; ?>">
						<?php echo esc_html( $label ); ?>
					</a>
				<?php endforeach; ?>
			</nav>

			<?php
			switch ( $active_tab ) {
				case self::TAB_SAFETY:
					SafetyTab::render();
					break;
				case self::TAB_BRIDGES:
					ConnectedBridgesTab::render();
					break;
				case self::TAB_ABILITIES:
				default:
					AbilitiesTab::render();
					break;
			}
			?>
		</div>
		<?php
	}

	/**
	 * Tab id → label.
	 *
	 * @return array<string,string>
	 */
	private static function tab_definitions(): array {
		return array(
			self::TAB_ABILITIES => __( 'Abilities', 'mcp-adapter' ),
			self::TAB_SAFETY    => __( 'Safety', 'mcp-adapter' ),
			self::TAB_BRIDGES   => __( 'Connected Bridges', 'mcp-adapter' ),
		);
	}
}
