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
	 * Register the admin page and hooks.
	 *
	 * @return void
	 */
	public static function register(): void {
		add_action( 'admin_menu', array( self::class, 'add_menu_page' ) );
		add_action( 'admin_init', array( self::class, 'handle_save' ) );
	}

	/**
	 * Add the Settings → Abilities menu page.
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
		wp_safe_redirect( add_query_arg(
			array(
				'page'    => self::PAGE_SLUG,
				'updated' => '1',
			),
			admin_url( 'options-general.php' )
		) );
		exit;
	}

	/**
	 * Render the settings page.
	 *
	 * @return void
	 */
	public static function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$abilities = wp_get_abilities();
		$grouped   = self::group_abilities_by_permission( $abilities );

		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'MCP Abilities', 'mcp-adapter' ); ?></h1>

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
