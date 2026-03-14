<?php
/**
 * Admin settings page for managing MCP Adapter ability permissions.
 *
 * Renders Settings → Abilities page with per-ability toggles grouped by permission type.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Admin;

/**
 * Admin settings page for ability permissions.
 */
class AbilitySettingsPage {

	/**
	 * The page slug.
	 */
	public const PAGE_SLUG = 'mcp-adapter-abilities';

	/**
	 * The nonce action.
	 */
	private const NONCE_ACTION = 'mcp_adapter_save_abilities';

	/**
	 * The license nonce action.
	 */
	private const LICENSE_NONCE_ACTION = 'mcp_adapter_license_nonce';

	/**
	 * Register the admin page and hooks.
	 *
	 * @return void
	 */
	public static function register(): void {
		add_action( 'admin_menu', array( self::class, 'add_menu_page' ) );
		add_action( 'network_admin_menu', array( self::class, 'add_network_menu_page' ) );
		add_action( 'admin_init', array( self::class, 'handle_save' ) );
		add_action( 'admin_init', array( self::class, 'handle_license_actions' ) );
	}

	/**
	 * Add the Settings → Abilities menu page (single site / subsite).
	 *
	 * @return void
	 */
	public static function add_menu_page(): void {
		add_options_page(
			__( 'MCP Abilities', 'mcp-adapter' ),
			__( 'MCP Abilities', 'mcp-adapter' ),
			'manage_options',
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	/**
	 * Add a top-level menu page in Network Admin.
	 *
	 * Network Admin has no Settings submenu, so we use a top-level page.
	 *
	 * @return void
	 */
	public static function add_network_menu_page(): void {
		add_menu_page(
			__( 'MCP Abilities', 'mcp-adapter' ),
			__( 'MCP Abilities', 'mcp-adapter' ),
			'manage_network_options',
			self::PAGE_SLUG,
			array( self::class, 'render_page' ),
			'dashicons-rest-api',
			81
		);
	}

	/**
	 * Get the admin URL for this settings page.
	 *
	 * @param array $args Optional query args.
	 * @return string
	 */
	private static function page_url( array $args = array() ): string {
		$args['page'] = self::PAGE_SLUG;
		if ( is_network_admin() ) {
			return add_query_arg( $args, network_admin_url( 'admin.php' ) );
		}
		return add_query_arg( $args, admin_url( 'options-general.php' ) );
	}

	/**
	 * Handle form submission to save ability settings.
	 *
	 * @return void
	 */
	public static function handle_save(): void {
		if ( ! isset( $_POST['mcp_adapter_abilities_nonce'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['mcp_adapter_abilities_nonce'] ) ), self::NONCE_ACTION ) ) {
			wp_die( esc_html__( 'Security check failed.', 'mcp-adapter' ) );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to manage ability settings.', 'mcp-adapter' ) );
		}

		$enabled_abilities = isset( $_POST['mcp_abilities_enabled'] ) && is_array( $_POST['mcp_abilities_enabled'] )
			? array_map( 'sanitize_text_field', wp_unslash( $_POST['mcp_abilities_enabled'] ) )
			: array();

		// Build settings: all abilities default to disabled, then enable checked ones.
		$abilities = wp_get_abilities();
		$settings  = array();

		foreach ( $abilities as $ability ) {
			$name = $ability->get_name();
			$meta = $ability->get_meta();

			// Only manage abilities that are MCP-exposed.
			if ( ! self::is_mcp_exposed( $ability ) ) {
				continue;
			}

			$settings[ $name ] = array(
				'enabled' => in_array( $name, $enabled_abilities, true ),
			);
		}

		PermissionManager::save_settings( $settings );

		// Redirect back with success message.
		wp_safe_redirect( self::page_url( array( 'updated' => '1' ) ) );
		exit;
	}

	/**
	 * Handle license activate/deactivate form submissions.
	 *
	 * @return void
	 */
	public static function handle_license_actions(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Activate.
		if ( isset( $_POST['mcp_adapter_license_activate'] ) ) {
			check_admin_referer( self::LICENSE_NONCE_ACTION );
			$key    = sanitize_text_field( wp_unslash( $_POST['mcp_adapter_license_key'] ?? '' ) );
			$result = \Abilities_MCP_Adapter_License_Manager::activate( $key );

			if ( is_wp_error( $result ) ) {
				add_settings_error( 'mcp_adapter_license', 'activation_failed', $result->get_error_message(), 'error' );
			} else {
				add_settings_error( 'mcp_adapter_license', 'activated', __( 'License activated successfully.', 'abilities-mcp-adapter' ), 'success' );
			}
			set_transient( 'settings_errors', get_settings_errors(), 30 );
			wp_safe_redirect( self::page_url( array( 'tab' => 'license', 'settings-updated' => 'true' ) ) );
			exit;
		}

		// Deactivate.
		if ( isset( $_POST['mcp_adapter_license_deactivate'] ) ) {
			check_admin_referer( self::LICENSE_NONCE_ACTION );
			\Abilities_MCP_Adapter_License_Manager::deactivate();
			add_settings_error( 'mcp_adapter_license', 'deactivated', __( 'License deactivated.', 'abilities-mcp-adapter' ), 'info' );
			set_transient( 'settings_errors', get_settings_errors(), 30 );
			wp_safe_redirect( self::page_url( array( 'tab' => 'license', 'settings-updated' => 'true' ) ) );
			exit;
		}
	}

	/**
	 * Render the settings page with tabs.
	 *
	 * @return void
	 */
	public static function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$active_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'abilities'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$saved      = isset( $_GET['settings-updated'] ) && 'true' === $_GET['settings-updated']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'MCP Abilities', 'mcp-adapter' ); ?></h1>
			<p style="font-size:13px;color:#646970;margin:0 0 16px;">
				v<?php echo esc_html( ABILITIES_MCP_ADAPTER_VERSION ); ?> — Abilities MCP Adapter
			</p>

			<?php if ( $saved ) : ?>
				<?php settings_errors( 'mcp_adapter_license' ); ?>
			<?php endif; ?>

			<nav class="nav-tab-wrapper">
				<a href="<?php echo esc_url( self::page_url( array( 'tab' => 'abilities' ) ) ); ?>"
				   class="nav-tab <?php echo 'abilities' === $active_tab ? 'nav-tab-active' : ''; ?>">
					Abilities
				</a>
				<a href="<?php echo esc_url( self::page_url( array( 'tab' => 'license' ) ) ); ?>"
				   class="nav-tab <?php echo 'license' === $active_tab ? 'nav-tab-active' : ''; ?>">
					License
				</a>
			</nav>

			<?php
			if ( 'license' === $active_tab ) {
				self::render_license_tab();
			} else {
				self::render_abilities_tab();
			}
			?>
		</div>
		<?php
	}

	/**
	 * Render the abilities tab.
	 *
	 * @return void
	 */
	private static function render_abilities_tab(): void {
		$abilities = wp_get_abilities();
		$grouped   = self::group_abilities_by_permission( $abilities );

		?>
		<?php if ( isset( $_GET['updated'] ) && '1' === $_GET['updated'] ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
			<div class="notice notice-success is-dismissible">
				<p><?php esc_html_e( 'Ability settings saved.', 'mcp-adapter' ); ?></p>
			</div>
		<?php endif; ?>

		<p><?php esc_html_e( 'Control which abilities are exposed via the MCP protocol. Disabled abilities remain visible to AI clients but return a structured permission error when called.', 'mcp-adapter' ); ?></p>

		<form method="post" action="">
			<?php wp_nonce_field( self::NONCE_ACTION, 'mcp_adapter_abilities_nonce' ); ?>

			<?php foreach ( $grouped as $permission => $group_abilities ) : ?>
				<h2>
					<?php
					switch ( $permission ) {
						case 'read':
							esc_html_e( 'Read Abilities', 'mcp-adapter' );
							break;
						case 'write':
							esc_html_e( 'Write Abilities', 'mcp-adapter' );
							break;
						case 'delete':
							esc_html_e( 'Delete Abilities', 'mcp-adapter' );
							break;
					}
					?>
				</h2>
				<table class="widefat striped">
					<thead>
						<tr>
							<th style="width:40px;"><?php esc_html_e( 'Enabled', 'mcp-adapter' ); ?></th>
							<th><?php esc_html_e( 'Ability', 'mcp-adapter' ); ?></th>
							<th><?php esc_html_e( 'Description', 'mcp-adapter' ); ?></th>
							<th><?php esc_html_e( 'Category', 'mcp-adapter' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $group_abilities as $ability ) : ?>
							<tr>
								<td>
									<input
										type="checkbox"
										name="mcp_abilities_enabled[]"
										value="<?php echo esc_attr( $ability->get_name() ); ?>"
										<?php checked( PermissionManager::is_enabled( $ability->get_name() ) ); ?>
									/>
								</td>
								<td><code><?php echo esc_html( $ability->get_name() ); ?></code></td>
								<td><?php echo esc_html( $ability->get_description() ); ?></td>
								<td><?php echo esc_html( $ability->get_category() ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endforeach; ?>

			<?php submit_button( __( 'Save Ability Settings', 'mcp-adapter' ) ); ?>
		</form>
		<?php
	}

	/**
	 * Render the license tab.
	 *
	 * @return void
	 */
	private static function render_license_tab(): void {
		$status    = \Abilities_MCP_Adapter_License_Manager::get_status();
		$is_active = $status['activated'];
		$has_key   = ! empty( $status['key'] );

		?>
		<div style="background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:24px;max-width:560px;margin:20px 0;box-shadow:0 1px 1px rgba(0,0,0,.04);">
			<h3 style="font-size:15px;font-weight:600;margin:0 0 14px;">
				Abilities MCP Adapter
			</h3>

			<?php if ( $is_active ) : ?>
				<div style="display:flex;align-items:center;gap:8px;margin:0 0 14px;font-size:13px;">
					<span style="width:10px;height:10px;border-radius:50%;background:#00a32a;display:inline-block;"></span>
					<strong style="color:#00a32a;"><?php esc_html_e( 'Active', 'abilities-mcp-adapter' ); ?></strong>
				</div>
				<form method="post">
					<?php wp_nonce_field( self::LICENSE_NONCE_ACTION ); ?>
					<div style="display:flex;gap:8px;margin:0 0 10px;">
						<input type="text" value="<?php echo esc_attr( $status['key'] ); ?>" disabled
							style="flex:1;padding:6px 10px;font-size:13px;border:1px solid #8c8f94;border-radius:4px;font-family:monospace;background:#f0f0f1;color:#50575e;">
						<button type="submit" name="mcp_adapter_license_deactivate" class="button"
							style="border-color:#d63638;color:#d63638;padding:2px 8px;font-size:12px;">Deactivate</button>
					</div>
				</form>
				<p style="font-size:12px;color:#646970;margin:0;">
					<span>Product ID: <?php echo esc_html( \Abilities_MCP_Adapter_License_Manager::PRODUCT_ID ); ?></span>
					<?php if ( ! empty( $status['last_valid'] ) ) : ?>
						<span style="margin-left:14px;">Last validated: <?php echo esc_html( $status['last_valid'] ); ?> UTC</span>
					<?php endif; ?>
				</p>

			<?php elseif ( $has_key ) : ?>
				<div style="display:flex;align-items:center;gap:8px;margin:0 0 14px;font-size:13px;">
					<span style="width:10px;height:10px;border-radius:50%;background:#d63638;display:inline-block;"></span>
					<strong style="color:#d63638;"><?php esc_html_e( 'Inactive', 'abilities-mcp-adapter' ); ?></strong>
				</div>
				<form method="post">
					<?php wp_nonce_field( self::LICENSE_NONCE_ACTION ); ?>
					<div style="display:flex;gap:8px;margin:0 0 10px;">
						<input type="text" value="<?php echo esc_attr( $status['key'] ); ?>" disabled
							style="flex:1;padding:6px 10px;font-size:13px;border:1px solid #8c8f94;border-radius:4px;font-family:monospace;background:#f0f0f1;color:#50575e;">
						<button type="submit" name="mcp_adapter_license_deactivate" class="button"
							style="border-color:#d63638;color:#d63638;padding:2px 8px;font-size:12px;">Remove</button>
					</div>
				</form>
				<p style="font-size:12px;color:#646970;margin:0;">
					License key stored but not active. Re-enter to activate.
				</p>

			<?php else : ?>
				<div style="display:flex;align-items:center;gap:8px;margin:0 0 14px;font-size:13px;">
					<span style="width:10px;height:10px;border-radius:50%;background:#dba617;display:inline-block;"></span>
					<strong style="color:#dba617;"><?php esc_html_e( 'No License', 'abilities-mcp-adapter' ); ?></strong>
				</div>
				<form method="post">
					<?php wp_nonce_field( self::LICENSE_NONCE_ACTION ); ?>
					<div style="display:flex;gap:8px;margin:0 0 10px;">
						<input type="text" name="mcp_adapter_license_key" placeholder="Enter your license key…"
							style="flex:1;padding:6px 10px;font-size:13px;border:1px solid #8c8f94;border-radius:4px;font-family:monospace;">
						<button type="submit" name="mcp_adapter_license_activate" class="button button-primary"
							style="padding:2px 8px;font-size:12px;">Activate</button>
					</div>
				</form>
				<p style="font-size:12px;color:#646970;margin:0;">
					A license key is required for automatic updates.
				</p>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Group abilities by their permission level.
	 *
	 * @param \WP_Ability[] $abilities All registered abilities.
	 *
	 * @return array<string, \WP_Ability[]> Abilities grouped by permission level.
	 */
	private static function group_abilities_by_permission( array $abilities ): array {
		$grouped = array(
			'read'   => array(),
			'write'  => array(),
			'delete' => array(),
		);

		foreach ( $abilities as $ability ) {
			// Only show MCP-exposed abilities.
			if ( ! self::is_mcp_exposed( $ability ) ) {
				continue;
			}

			$permission = PermissionManager::get_permission( $ability );
			if ( ! isset( $grouped[ $permission ] ) ) {
				$grouped[ $permission ] = array();
			}
			$grouped[ $permission ][] = $ability;
		}

		// Remove empty groups.
		return array_filter( $grouped );
	}

	/**
	 * Check if an ability is MCP-exposed (show_in_rest or mcp.public).
	 *
	 * @param \WP_Ability $ability The ability object.
	 *
	 * @return bool True if exposed.
	 */
	private static function is_mcp_exposed( \WP_Ability $ability ): bool {
		if ( method_exists( $ability, 'get_show_in_rest' ) ) {
			$show_in_rest = $ability->get_show_in_rest();
			if ( null !== $show_in_rest ) {
				return (bool) $show_in_rest;
			}
		}

		$meta = $ability->get_meta();
		return (bool) ( $meta['mcp']['public'] ?? false );
	}
}
