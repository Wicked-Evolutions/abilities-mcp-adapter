<?php
/**
 * Ability for onboarding — returns site capabilities summary for AI clients.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Abilities;

/**
 * Get Started — Returns a structured onboarding response for AI clients.
 *
 * Provides: available modules, total tool count, user permission level,
 * enabled/disabled abilities summary, and recommended first steps.
 * AI calls this on first connection and explains the site's capabilities to the user.
 */
final class GetStartedAbility {
	use McpAbilityHelperTrait;

	/**
	 * Register the ability.
	 */
	public static function register(): void {
		wp_register_ability(
			'mcp-adapter/get-started',
			array(
				'label'               => 'Get Started',
				'description'         => 'Returns a structured onboarding summary of this WordPress site: available ability modules, total tool count, current user permissions, and recommended first steps. Call this first when connecting to a new site.',
				'category'            => 'mcp-adapter',
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'site_name'        => array( 'type' => 'string' ),
						'site_url'         => array( 'type' => 'string' ),
						'wordpress_version' => array( 'type' => 'string' ),
						'user'             => array(
							'type'       => 'object',
							'properties' => array(
								'display_name' => array( 'type' => 'string' ),
								'role'         => array( 'type' => 'string' ),
							),
						),
						'abilities'        => array(
							'type'       => 'object',
							'properties' => array(
								'total'      => array( 'type' => 'integer' ),
								'enabled'    => array( 'type' => 'integer' ),
								'disabled'   => array( 'type' => 'integer' ),
								'categories' => array(
									'type'  => 'array',
									'items' => array(
										'type'       => 'object',
										'properties' => array(
											'slug'  => array( 'type' => 'string' ),
											'label' => array( 'type' => 'string' ),
											'count' => array( 'type' => 'integer' ),
										),
									),
								),
							),
						),
						'recommended_first_steps' => array(
							'type'  => 'array',
							'items' => array( 'type' => 'string' ),
						),
					),
				),
				'permission_callback' => array( self::class, 'check_permission' ),
				'execute_callback'    => array( self::class, 'execute' ),
				'meta'                => array(
					'mcp'         => array( 'public' => true ),
					'annotations' => array(
						'readonly'    => true,
						'destructive' => false,
						'idempotent'  => true,
					),
				),
			)
		);
	}

	/**
	 * Check permissions.
	 *
	 * @param array $input Input parameters (unused).
	 *
	 * @return bool|\WP_Error True if permitted.
	 */
	public static function check_permission( $input = array() ) {
		if ( ! is_user_logged_in() ) {
			return new \WP_Error( 'authentication_required', 'User must be authenticated to access this ability' );
		}

		$required_capability = apply_filters( 'mcp_adapter_get_started_capability', 'read' );
		// phpcs:ignore WordPress.WP.Capabilities.Undetermined -- Capability is determined dynamically via filter
		if ( ! current_user_can( $required_capability ) ) {
			return new \WP_Error(
				'insufficient_capability',
				sprintf( 'User lacks required capability: %s', $required_capability )
			);
		}

		return true;
	}

	/**
	 * Execute — gather and return the onboarding summary.
	 *
	 * @param array $input Input parameters (unused).
	 *
	 * @return array Onboarding summary.
	 */
	public static function execute( $input = array() ): array {
		$permission_check = self::check_permission( $input );
		if ( is_wp_error( $permission_check ) ) {
			return array( 'error' => $permission_check->get_error_message() );
		}

		// Site info.
		$site_name         = get_bloginfo( 'name' );
		$site_url          = get_site_url();
		$wordpress_version = get_bloginfo( 'version' );

		// Current user.
		$user         = wp_get_current_user();
		$roles        = $user->roles;
		$primary_role = ! empty( $roles ) ? reset( $roles ) : 'none';

		// Abilities breakdown.
		$abilities      = wp_get_abilities();
		$total          = 0;
		$enabled_count  = 0;
		$disabled_count = 0;
		$category_counts = array();

		$adapter_settings = get_option( 'mcp_adapter_settings', array() );
		$disabled_tools   = isset( $adapter_settings['disabled_tools'] ) && is_array( $adapter_settings['disabled_tools'] )
			? $adapter_settings['disabled_tools']
			: array();

		foreach ( $abilities as $ability ) {
			if ( ! self::is_ability_mcp_public( $ability ) ) {
				continue;
			}
			if ( self::get_ability_mcp_type( $ability ) !== 'tool' ) {
				continue;
			}

			++$total;
			$ability_name = $ability->get_name();

			if ( in_array( $ability_name, $disabled_tools, true ) ) {
				++$disabled_count;
			} else {
				++$enabled_count;
			}

			$category = $ability->get_category();
			if ( ! isset( $category_counts[ $category ] ) ) {
				$category_counts[ $category ] = 0;
			}
			++$category_counts[ $category ];
		}

		// Build category list with labels.
		$categories_list = array();
		$registered_categories = wp_get_ability_categories();
		foreach ( $category_counts as $slug => $count ) {
			$label = $slug;
			if ( isset( $registered_categories[ $slug ] ) ) {
				$cat = $registered_categories[ $slug ];
				if ( method_exists( $cat, 'get_label' ) ) {
					$label = $cat->get_label();
				}
			}
			$categories_list[] = array(
				'slug'  => $slug,
				'label' => $label,
				'count' => $count,
			);
		}

		// Sort by count descending.
		usort(
			$categories_list,
			function ( $a, $b ) {
				return $b['count'] - $a['count'];
			}
		);

		// Recommended first steps.
		$steps = array();

		if ( $disabled_count > 0 ) {
			$steps[] = sprintf(
				'%d abilities are disabled by the site administrator. Ask the site owner to enable them in MCP Adapter settings if needed.',
				$disabled_count
			);
		}

		if ( 'administrator' !== $primary_role ) {
			$steps[] = sprintf(
				'You are connected as "%s" (role: %s). Some abilities may require higher permissions.',
				$user->display_name,
				$primary_role
			);
		}

		// Build the response.
		$response = array(
			'site_name'              => $site_name,
			'site_url'               => $site_url,
			'wordpress_version'      => $wordpress_version,
			'user'                   => array(
				'display_name' => $user->display_name,
				'role'         => $primary_role,
			),
			'abilities'              => array(
				'total'      => $total,
				'enabled'    => $enabled_count,
				'disabled'   => $disabled_count,
				'categories' => $categories_list,
			),
			'recommended_first_steps' => $steps,
		);

		// Knowledge Layer integration — if knowledge/boot exists, direct AI there.
		$has_knowledge_boot = isset( $abilities['knowledge/boot'] );
		if ( $has_knowledge_boot ) {
			$response['next_action'] = array(
				'ability'     => 'knowledge/boot',
				'instruction' => 'This site has a Knowledge Layer. Call knowledge/boot now — it will orient you to the site and tell you what to do next. Do not browse abilities or make other calls until you have completed the boot sequence.',
			);
		} else {
			// Fallback for sites without Knowledge Layer.
			array_unshift( $steps, 'Use "mcp-adapter/discover-abilities" to browse all available tools by category.' );
			$steps[] = 'Use "mcp-adapter/get-ability-info" to see detailed schema for any specific tool.';
			$steps[] = 'Content tools (content/list, content/get, content/create) are a good starting point.';
			$response['recommended_first_steps'] = $steps;
		}

		return $response;
	}
}
