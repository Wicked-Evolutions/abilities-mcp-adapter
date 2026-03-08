<?php
/**
 * Permission Manager for MCP Adapter abilities.
 *
 * Manages per-ability permission levels and enabled/disabled state.
 * Permission levels are derived from ability annotations or explicit metadata.
 * Enabled state is stored in WordPress options for admin control.
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Admin;

/**
 * Manages ability permissions and enabled state for the MCP Adapter.
 */
class PermissionManager {

	/**
	 * WordPress option name for ability settings.
	 */
	public const OPTION_NAME = 'mcp_adapter_ability_settings';

	/**
	 * Valid permission levels.
	 */
	public const PERMISSION_READ   = 'read';
	public const PERMISSION_WRITE  = 'write';
	public const PERMISSION_DELETE = 'delete';

	/**
	 * All valid permission values.
	 *
	 * @var string[]
	 */
	public const VALID_PERMISSIONS = array(
		self::PERMISSION_READ,
		self::PERMISSION_WRITE,
		self::PERMISSION_DELETE,
	);

	/**
	 * Cached settings from the database.
	 *
	 * @var array|null
	 */
	private static ?array $cached_settings = null;

	/**
	 * Get the permission level for an ability.
	 *
	 * Priority:
	 * 1. Explicit `permission` in ability meta.annotations
	 * 2. Derived from annotations: readonly=true → read, destructive=true → delete, else → write
	 * 3. Default: read
	 *
	 * @param \WP_Ability $ability The ability object.
	 *
	 * @return string Permission level: 'read', 'write', or 'delete'.
	 */
	public static function get_permission( \WP_Ability $ability ): string {
		$meta        = $ability->get_meta();
		$annotations = $meta['annotations'] ?? array();

		// 1. Explicit permission in annotations.
		if ( isset( $annotations['permission'] ) && in_array( $annotations['permission'], self::VALID_PERMISSIONS, true ) ) {
			return $annotations['permission'];
		}

		// 2. Derive from readonly/destructive annotations.
		if ( ! empty( $annotations['readonly'] ) ) {
			return self::PERMISSION_READ;
		}
		if ( ! empty( $annotations['destructive'] ) ) {
			return self::PERMISSION_DELETE;
		}

		// If neither readonly nor destructive, it's a write operation.
		// But only if annotations exist — otherwise default to read.
		if ( isset( $annotations['readonly'] ) || isset( $annotations['destructive'] ) ) {
			return self::PERMISSION_WRITE;
		}

		// 3. Default.
		return self::PERMISSION_READ;
	}

	/**
	 * Check if an ability is enabled for MCP exposure.
	 *
	 * Abilities default to enabled. Admin can disable specific abilities
	 * via the Settings → Abilities page.
	 *
	 * @param string $ability_name The ability name.
	 *
	 * @return bool True if enabled, false if disabled.
	 */
	public static function is_enabled( string $ability_name ): bool {
		$settings = self::get_settings();

		// Default to enabled if no setting exists.
		if ( ! isset( $settings[ $ability_name ] ) ) {
			return true;
		}

		return ! empty( $settings[ $ability_name ]['enabled'] );
	}

	/**
	 * Set the enabled state for an ability.
	 *
	 * @param string $ability_name The ability name.
	 * @param bool   $enabled      Whether the ability is enabled.
	 *
	 * @return bool True on success, false on failure.
	 */
	public static function set_enabled( string $ability_name, bool $enabled ): bool {
		$settings = self::get_settings();

		if ( ! isset( $settings[ $ability_name ] ) ) {
			$settings[ $ability_name ] = array();
		}

		$settings[ $ability_name ]['enabled'] = $enabled;
		self::$cached_settings                = $settings;

		return update_option( self::OPTION_NAME, $settings, false );
	}

	/**
	 * Get all stored ability settings.
	 *
	 * @return array Associative array of ability_name => settings.
	 */
	public static function get_settings(): array {
		if ( null !== self::$cached_settings ) {
			return self::$cached_settings;
		}

		$settings = get_option( self::OPTION_NAME, array() );
		if ( ! is_array( $settings ) ) {
			$settings = array();
		}

		self::$cached_settings = $settings;

		return $settings;
	}

	/**
	 * Save bulk ability settings (used by admin page).
	 *
	 * @param array $settings Associative array of ability_name => settings.
	 *
	 * @return bool True on success.
	 */
	public static function save_settings( array $settings ): bool {
		self::$cached_settings = $settings;

		return update_option( self::OPTION_NAME, $settings, false );
	}

	/**
	 * Clear the settings cache (useful for testing).
	 *
	 * @return void
	 */
	public static function clear_cache(): void {
		self::$cached_settings = null;
	}

	/**
	 * Validate a permission value.
	 *
	 * @param string $permission The permission value to validate.
	 *
	 * @return bool True if valid.
	 */
	public static function is_valid_permission( string $permission ): bool {
		return in_array( $permission, self::VALID_PERMISSIONS, true );
	}
}
