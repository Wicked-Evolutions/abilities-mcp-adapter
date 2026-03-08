<?php
/**
 * Helper trait for WordPress abilities providing MCP-related utilities.
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Abilities;

/**
 * Trait McpAbilityHelperTrait
 *
 * Provides helper methods for MCP abilities including MCP exposure checking and metadata handling.
 */
trait McpAbilityHelperTrait {

	/**
	 * Checks if ability is publicly exposed via MCP.
	 *
	 * Discovery gate priority (XP5):
	 * 1. `show_in_rest` ability property (WordPress core standard)
	 * 2. `mcp.public` metadata flag (backward compatibility fallback)
	 *
	 * @param string $ability_name The ability name to check.
	 *
	 * @return bool|\WP_Error True if publicly exposed, WP_Error if not.
	 */
	protected static function check_ability_mcp_exposure( string $ability_name ) {
		$ability = wp_get_ability( $ability_name );

		if ( ! $ability ) {
			return new \WP_Error( 'ability_not_found', "Ability '{$ability_name}' not found" );
		}

		if ( ! self::is_ability_mcp_public( $ability ) ) {
			return new \WP_Error(
				'ability_not_public_mcp',
				sprintf( 'Ability "%s" is not exposed via MCP', $ability_name )
			);
		}

		return true;
	}

	/**
	 * Checks if ability is publicly exposed via MCP (simple boolean version).
	 *
	 * Discovery gate priority (XP5):
	 * 1. `show_in_rest` ability property (WordPress core standard)
	 * 2. `mcp.public` metadata flag (backward compatibility fallback)
	 *
	 * @param \WP_Ability $ability The ability object to check.
	 *
	 * @return bool True if publicly exposed, false otherwise.
	 */
	protected static function is_ability_mcp_public( \WP_Ability $ability ): bool {
		// Primary gate: show_in_rest (WordPress core standard).
		if ( method_exists( $ability, 'get_show_in_rest' ) ) {
			$show_in_rest = $ability->get_show_in_rest();
			if ( null !== $show_in_rest ) {
				return (bool) $show_in_rest;
			}
		}

		// Fallback: mcp.public metadata flag.
		$meta = $ability->get_meta();
		return (bool) ( $meta['mcp']['public'] ?? false );
	}

	/**
	 * Gets the MCP type of an ability.
	 *
	 * Returns the type specified in meta.mcp.type, defaulting to 'tool' if not specified.
	 *
	 * @param \WP_Ability $ability The ability object to check.
	 *
	 * @return string The MCP type ('tool', 'resource', or 'prompt'). Defaults to 'tool'.
	 */
	protected static function get_ability_mcp_type( \WP_Ability $ability ): string {
		$meta = $ability->get_meta();
		$type = $meta['mcp']['type'] ?? 'tool';

		// Validate type is one of the allowed values
		if ( ! in_array( $type, array( 'tool', 'resource', 'prompt' ), true ) ) {
			return 'tool';
		}

		return $type;
	}
}
