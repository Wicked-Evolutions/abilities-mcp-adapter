<?php
/**
 * Plugin Name: Abilities MCP Adapter
 * Plugin URI:  https://github.com/Wicked-Evolutions/abilities-mcp-adapter
 * Description: Exposes WordPress abilities as MCP tools, resources, and prompts. Upload, activate, and your WordPress abilities become MCP tools.
 * Version:     1.3.0
 * Author:      Wicked Evolutions
 * Author URI:  https://wickedevolutions.com
 * Copyright:   Copyright (C) 2026 Wicked Evolutions
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 6.9
 * Requires PHP: 8.0
 */

defined( 'ABSPATH' ) || exit;

// Plugin constants.
define( 'ABILITIES_MCP_ADAPTER_VERSION', '1.3.0' );
define( 'ABILITIES_MCP_ADAPTER_PATH', plugin_dir_path( __FILE__ ) );

// License manager — FluentCart license for auto-update delivery.
require_once ABILITIES_MCP_ADAPTER_PATH . 'includes/class-license-manager.php';

// Plugin updater — checks FluentCart for new versions.
require_once ABILITIES_MCP_ADAPTER_PATH . 'includes/updater/class-plugin-updater.php';

new Abilities_MCP_Adapter_Plugin_Updater( array(
	'slug'                 => 'abilities-mcp-adapter',
	'basename'             => plugin_basename( __FILE__ ),
	'version'              => ABILITIES_MCP_ADAPTER_VERSION,
	'item_id'              => Abilities_MCP_Adapter_License_Manager::get_product_id(),
	'api_url'              => Abilities_MCP_Adapter_License_Manager::STORE_URL,
	'license_key_callback' => array( 'Abilities_MCP_Adapter_License_Manager', 'get_license_key' ),
	'github_repo'          => 'Wicked-Evolutions/abilities-mcp-adapter',
	'show_check_update'    => true,
) );

// Composer PSR-4 autoloader.
$autoloader = plugin_dir_path( __FILE__ ) . 'vendor/autoload.php';
if ( file_exists( $autoloader ) ) {
	require_once $autoloader;
} else {
	error_log( 'MCP Adapter: Composer autoloader not found. Run composer install.' );
	return;
}

use WickedEvolutions\McpAdapter\Core\McpAdapter;
use WickedEvolutions\McpAdapter\Admin\AbilitySettingsPage;

// Register admin settings page (license + ability permissions).
if ( is_admin() ) {
	AbilitySettingsPage::register();
}

// Enable MCP tool validation — silently drops invalid tools instead of breaking all tools.
add_filter( 'mcp_adapter_validation_enabled', '__return_true' );

// Configure the default MCP server: discovery gate (XP5) — show_in_rest with mcp.public fallback.
add_filter( 'mcp_adapter_default_server_config', function( $config ) {
	$tools = array(
		'mcp-adapter/discover-abilities',
		'mcp-adapter/get-ability-info',
		'mcp-adapter/execute-ability',
		'mcp-adapter/batch-execute',
	);
	foreach ( wp_get_abilities() as $name => $ability ) {
		// Discovery gate (XP5): show_in_rest with mcp.public fallback.
		$is_public = false;
		if ( method_exists( $ability, 'get_show_in_rest' ) ) {
			$show_in_rest = $ability->get_show_in_rest();
			if ( null !== $show_in_rest ) {
				$is_public = (bool) $show_in_rest;
			}
		}
		if ( ! $is_public ) {
			$meta      = $ability->get_meta();
			$is_public = (bool) ( $meta['mcp']['public'] ?? false );
		}
		if ( ! $is_public ) {
			continue;
		}
		// Default type is 'tool'; skip abilities registered as resources or prompts.
		$meta = $ability->get_meta();
		$type = $meta['mcp']['type'] ?? 'tool';
		if ( 'tool' !== $type ) {
			continue;
		}
		$tools[] = $name;
	}
	$config['tools'] = $tools;
	return $config;
}, 10 );

// Initialize the MCP Adapter.
add_action( 'init', function() {
	if ( ! class_exists( McpAdapter::class ) ) {
		return;
	}
	McpAdapter::instance();
}, 5 );
