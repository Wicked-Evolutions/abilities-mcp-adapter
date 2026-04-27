<?php
/**
 * Abilities tab — migrated from AbilitySettingsPage.
 *
 * Preserves every setting and action from the legacy
 * options-general.php?page=mcp-adapter-abilities page:
 *
 *   - Per-ability enable/disable checkbox grouped by permission level
 *     (read / write / delete), saved through PermissionManager.
 *   - License sub-tab: activate / deactivate / remove via the
 *     Abilities_MCP_Adapter_License_Manager.
 *
 * Sub-tabs are rendered as a second-level <h2 class="nav-tab-wrapper"> bar
 * inside the consolidated page, so the Settings → Abilities MCP Adapter →
 * Abilities tab still lets the operator switch between "Abilities" and
 * "License" without leaving the new menu entry.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Admin\Tabs;

use WickedEvolutions\McpAdapter\Admin\AdapterAdminPage;
use WickedEvolutions\McpAdapter\Admin\PermissionManager;

/**
 * Abilities tab renderer + form handlers.
 */
final class AbilitiesTab {

	/** Sub-tab ids inside the Abilities tab. */
	public const SUBTAB_ABILITIES = 'abilities';
	public const SUBTAB_LICENSE   = 'license';

	/** Nonce action for the per-ability save form. */
	public const NONCE_ACTION = 'mcp_adapter_save_abilities';

	/** Nonce action for license activate/deactivate. */
	public const LICENSE_NONCE_ACTION = 'mcp_adapter_license_nonce';

	/**
	 * Handle the per-ability save form submission.
	 *
	 * Mirrors AbilitySettingsPage::handle_save() exactly so existing operator
	 * muscle memory (and the saved option payload) is preserved.
	 */
	public static function handle_save_abilities(): void {
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

		$abilities = wp_get_abilities();
		$settings  = array();

		foreach ( $abilities as $ability ) {
			if ( ! self::is_mcp_exposed( $ability ) ) {
				continue;
			}
			$name              = $ability->get_name();
			$settings[ $name ] = array(
				'enabled' => in_array( $name, $enabled_abilities, true ),
			);
		}

		PermissionManager::save_settings( $settings );

		wp_safe_redirect(
			AdapterAdminPage::tab_url( AdapterAdminPage::TAB_ABILITIES, array(
				'subtab'  => self::SUBTAB_ABILITIES,
				'updated' => '1',
			) )
		);
		exit;
	}

	/**
	 * Handle license activate / deactivate / remove submissions.
	 *
	 * Behaviour identical to AbilitySettingsPage::handle_license_actions().
	 */
	public static function handle_license_actions(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

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
			wp_safe_redirect(
				AdapterAdminPage::tab_url( AdapterAdminPage::TAB_ABILITIES, array(
					'subtab'           => self::SUBTAB_LICENSE,
					'settings-updated' => 'true',
				) )
			);
			exit;
		}

		if ( isset( $_POST['mcp_adapter_license_deactivate'] ) ) {
			check_admin_referer( self::LICENSE_NONCE_ACTION );
			\Abilities_MCP_Adapter_License_Manager::deactivate();
			add_settings_error( 'mcp_adapter_license', 'deactivated', __( 'License deactivated.', 'abilities-mcp-adapter' ), 'info' );
			set_transient( 'settings_errors', get_settings_errors(), 30 );
			wp_safe_redirect(
				AdapterAdminPage::tab_url( AdapterAdminPage::TAB_ABILITIES, array(
					'subtab'           => self::SUBTAB_LICENSE,
					'settings-updated' => 'true',
				) )
			);
			exit;
		}
	}

	/**
	 * Render the Abilities tab body.
	 */
	public static function render(): void {
		$active_subtab = self::active_subtab();

		?>
		<h2 class="nav-tab-wrapper wp-mcp-adapter-subtabs">
			<a href="<?php echo esc_url( AdapterAdminPage::tab_url( AdapterAdminPage::TAB_ABILITIES, array( 'subtab' => self::SUBTAB_ABILITIES ) ) ); ?>"
			   class="nav-tab <?php echo self::SUBTAB_ABILITIES === $active_subtab ? 'nav-tab-active' : ''; ?>">
				<?php esc_html_e( 'Abilities', 'mcp-adapter' ); ?>
			</a>
			<a href="<?php echo esc_url( AdapterAdminPage::tab_url( AdapterAdminPage::TAB_ABILITIES, array( 'subtab' => self::SUBTAB_LICENSE ) ) ); ?>"
			   class="nav-tab <?php echo self::SUBTAB_LICENSE === $active_subtab ? 'nav-tab-active' : ''; ?>">
				<?php esc_html_e( 'License', 'mcp-adapter' ); ?>
			</a>
		</h2>

		<?php
		if ( self::SUBTAB_LICENSE === $active_subtab ) {
			self::render_license_subtab();
		} else {
			self::render_abilities_subtab();
		}
	}

	/**
	 * Resolve the active sub-tab from $_GET.
	 */
	public static function active_subtab(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only sub-tab switch.
		$requested = isset( $_GET['subtab'] ) ? sanitize_key( wp_unslash( (string) $_GET['subtab'] ) ) : self::SUBTAB_ABILITIES;
		return self::SUBTAB_LICENSE === $requested ? self::SUBTAB_LICENSE : self::SUBTAB_ABILITIES;
	}

	/**
	 * Render the per-ability checkbox grid.
	 */
	private static function render_abilities_subtab(): void {
		$abilities = wp_get_abilities();
		$grouped   = self::group_abilities_by_permission( $abilities );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Flash flag from PRG redirect.
		if ( isset( $_GET['updated'] ) && '1' === $_GET['updated'] ) :
			?>
			<div class="notice notice-success is-dismissible">
				<p><?php esc_html_e( 'Ability settings saved.', 'mcp-adapter' ); ?></p>
			</div>
			<?php
		endif;
		?>

		<p><?php esc_html_e( 'Control which abilities are exposed via the MCP protocol. Disabled abilities remain visible to AI clients but return a structured permission error when called.', 'mcp-adapter' ); ?></p>

		<form method="post" action="">
			<?php wp_nonce_field( self::NONCE_ACTION, 'mcp_adapter_abilities_nonce' ); ?>

			<?php foreach ( $grouped as $permission => $group_abilities ) : ?>
				<h2>
					<?php
					switch ( $permission ) {
						case PermissionManager::PERMISSION_READ:
							esc_html_e( 'Read Abilities', 'mcp-adapter' );
							break;
						case PermissionManager::PERMISSION_WRITE:
							esc_html_e( 'Write Abilities', 'mcp-adapter' );
							break;
						case PermissionManager::PERMISSION_DELETE:
							esc_html_e( 'Delete Abilities', 'mcp-adapter' );
							break;
					}
					?>
				</h2>
				<table class="widefat striped wp-mcp-adapter-table">
					<thead>
						<tr>
							<th class="wp-mcp-adapter-col-narrow"><?php esc_html_e( 'Enabled', 'mcp-adapter' ); ?></th>
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
	 * Render the license sub-tab.
	 */
	private static function render_license_subtab(): void {
		$status    = \Abilities_MCP_Adapter_License_Manager::get_status();
		$is_active = ! empty( $status['activated'] );
		$has_key   = ! empty( $status['key'] );

		?>
		<div class="wp-mcp-adapter-card wp-mcp-adapter-card--narrow">
			<h3 class="wp-mcp-adapter-card-title"><?php esc_html_e( 'Abilities MCP Adapter', 'mcp-adapter' ); ?></h3>

			<?php if ( $is_active ) : ?>
				<div class="wp-mcp-adapter-status">
					<span class="wp-mcp-adapter-status-dot wp-mcp-adapter-status-dot--ok"></span>
					<strong class="wp-mcp-adapter-status-label--ok"><?php esc_html_e( 'Active', 'abilities-mcp-adapter' ); ?></strong>
				</div>
				<form method="post">
					<?php wp_nonce_field( self::LICENSE_NONCE_ACTION ); ?>
					<div class="wp-mcp-adapter-inline-row">
						<input type="text" class="wp-mcp-adapter-input-grow" value="<?php echo esc_attr( $status['key'] ); ?>" disabled />
						<button type="submit" name="mcp_adapter_license_deactivate" class="button"><?php esc_html_e( 'Deactivate', 'abilities-mcp-adapter' ); ?></button>
					</div>
				</form>
				<p class="wp-mcp-adapter-hint">
					<span><?php
					echo esc_html(
						sprintf(
							/* translators: %s: product id */
							__( 'Product ID: %s', 'abilities-mcp-adapter' ),
							\Abilities_MCP_Adapter_License_Manager::PRODUCT_ID
						)
					);
					?></span>
					<?php if ( ! empty( $status['last_valid'] ) ) : ?>
						<span class="wp-mcp-adapter-hint-sep"><?php
						echo esc_html(
							sprintf(
								/* translators: %s: timestamp */
								__( 'Last validated: %s UTC', 'abilities-mcp-adapter' ),
								$status['last_valid']
							)
						);
						?></span>
					<?php endif; ?>
				</p>

			<?php elseif ( $has_key ) : ?>
				<div class="wp-mcp-adapter-status">
					<span class="wp-mcp-adapter-status-dot wp-mcp-adapter-status-dot--err"></span>
					<strong class="wp-mcp-adapter-status-label--err"><?php esc_html_e( 'Inactive', 'abilities-mcp-adapter' ); ?></strong>
				</div>
				<form method="post">
					<?php wp_nonce_field( self::LICENSE_NONCE_ACTION ); ?>
					<div class="wp-mcp-adapter-inline-row">
						<input type="text" class="wp-mcp-adapter-input-grow" value="<?php echo esc_attr( $status['key'] ); ?>" disabled />
						<button type="submit" name="mcp_adapter_license_deactivate" class="button"><?php esc_html_e( 'Remove', 'abilities-mcp-adapter' ); ?></button>
					</div>
				</form>
				<p class="wp-mcp-adapter-hint">
					<?php esc_html_e( 'License key stored but not active. Re-enter to activate.', 'abilities-mcp-adapter' ); ?>
				</p>

			<?php else : ?>
				<div class="wp-mcp-adapter-status">
					<span class="wp-mcp-adapter-status-dot wp-mcp-adapter-status-dot--warn"></span>
					<strong class="wp-mcp-adapter-status-label--warn"><?php esc_html_e( 'No License', 'abilities-mcp-adapter' ); ?></strong>
				</div>
				<form method="post">
					<?php wp_nonce_field( self::LICENSE_NONCE_ACTION ); ?>
					<div class="wp-mcp-adapter-inline-row">
						<input type="text" class="wp-mcp-adapter-input-grow" name="mcp_adapter_license_key" placeholder="<?php esc_attr_e( 'Enter your license key…', 'abilities-mcp-adapter' ); ?>" />
						<button type="submit" name="mcp_adapter_license_activate" class="button button-primary"><?php esc_html_e( 'Activate', 'abilities-mcp-adapter' ); ?></button>
					</div>
				</form>
				<p class="wp-mcp-adapter-hint">
					<?php esc_html_e( 'A license key is required for automatic updates.', 'abilities-mcp-adapter' ); ?>
				</p>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Group abilities by permission level (read/write/delete).
	 *
	 * @param \WP_Ability[] $abilities All registered abilities.
	 *
	 * @return array<string, \WP_Ability[]>
	 */
	private static function group_abilities_by_permission( array $abilities ): array {
		$grouped = array(
			PermissionManager::PERMISSION_READ   => array(),
			PermissionManager::PERMISSION_WRITE  => array(),
			PermissionManager::PERMISSION_DELETE => array(),
		);

		foreach ( $abilities as $ability ) {
			if ( ! self::is_mcp_exposed( $ability ) ) {
				continue;
			}
			$permission = PermissionManager::get_permission( $ability );
			if ( ! isset( $grouped[ $permission ] ) ) {
				$grouped[ $permission ] = array();
			}
			$grouped[ $permission ][] = $ability;
		}

		return array_filter( $grouped );
	}

	/**
	 * Whether an ability is MCP-exposed (show_in_rest or mcp.public).
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
