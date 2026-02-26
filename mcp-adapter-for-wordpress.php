<?php
/**
 * Plugin Name: MCP Adapter for WordPress
 * Plugin URI:  https://github.com/Influencentricity/mcp-adapter-for-wordpress
 * Description: Packages the official WordPress MCP Adapter as an installable plugin with automatic ability discovery. Upload, activate, and your WordPress abilities become MCP tools.
 * Version:     2.2.0
 * Author:      Influencentricity
 * Author URI:  https://influencentricity.com
 * License:     GPL-2.0-or-later
 * Requires at least: 6.9
 * Requires PHP: 7.4
 */

defined( 'ABSPATH' ) || exit;

if ( file_exists( plugin_dir_path( __FILE__ ) . 'vendor/autoload_packages.php' ) ) {
	require_once plugin_dir_path( __FILE__ ) . 'vendor/autoload_packages.php';
} else {
	error_log( 'MCP Adapter: Composer dependencies not found. Run composer install.' );
	return;
}

use WP\MCP\Core\McpAdapter;

// Enable MCP tool validation — silently drops invalid tools instead of breaking all tools.
add_filter( 'mcp_adapter_validation_enabled', '__return_true' );

// Configure the default MCP server to expose only abilities flagged mcp.public=true and mcp.type='tool'.
add_filter( 'mcp_adapter_default_server_config', function( $config ) {
	$tools = array(
		'mcp-adapter/discover-abilities',
		'mcp-adapter/get-ability-info',
		'mcp-adapter/execute-ability',
	);
	foreach ( wp_get_abilities() as $name => $ability ) {
		$meta = $ability->get_meta();
		// Only expose abilities explicitly marked as public MCP tools.
		if ( ! ( $meta['mcp']['public'] ?? false ) ) {
			continue;
		}
		// Default type is 'tool'; skip abilities registered as resources or prompts.
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
