<?php
/**
 * Ability for discovering available WordPress abilities.
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
 * Discover Abilities - Lists all available WordPress abilities in the system.
 *
 * This ability provides discovery functionality for the MCP protocol.
 * It discovers all registered WordPress abilities in the system.
 *
 * SECURITY CONSIDERATIONS:
 * - This ability exposes information about all registered abilities in the system
 * - Only abilities with mcp.public=true metadata will be returned
 * - Requires proper WordPress capability checks for secure operation
 *
 * @see https://github.com/Wicked-Evolutions/abilities-mcp-adapter for detailed security configuration
 */
final class DiscoverAbilitiesAbility {
	use McpAbilityHelperTrait;

	/**
	 * Register the ability.
	 */
	public static function register(): void {
		wp_register_ability(
			'mcp-adapter/discover-abilities',
			array(
				'label'               => 'Discover Abilities',
				'description'         => 'Lists registered WordPress abilities. Supports filtering by category, annotation, and search. Without filters returns the full manifest (~77KB). Use filters to keep responses lean.',
				'category'            => 'mcp-adapter',
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'category'   => array(
							'type'        => 'string',
							'description' => 'Filter by ability category slug (e.g. "content", "taxonomies", "knowledge").',
						),
						'annotation' => array(
							'type'        => 'string',
							'enum'        => array( 'readonly', 'destructive' ),
							'description' => 'Filter by meta annotation: "readonly" for safe read operations, "destructive" for delete operations.',
						),
						'search'     => array(
							'type'        => 'string',
							'description' => 'Keyword search in ability name and description.',
						),
						'compact'    => array(
							'type'        => 'boolean',
							'description' => 'When true, returns only name, category, and tier — no descriptions or schemas. Reduces response from ~128KB to ~8KB at scale.',
							'default'     => false,
						),
						'limit'      => array(
							'type'        => 'integer',
							'description' => 'Maximum number of abilities to return. Use with offset for pagination.',
							'minimum'     => 1,
							'maximum'     => 200,
						),
						'offset'     => array(
							'type'        => 'integer',
							'description' => 'Number of abilities to skip before returning results. Use with limit for pagination.',
							'minimum'     => 0,
							'default'     => 0,
						),
					),
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'abilities' => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'name'        => array( 'type' => 'string' ),
									'label'       => array( 'type' => 'string' ),
									'description' => array( 'type' => 'string' ),
									'category'    => array( 'type' => 'string' ),
									'tier'        => array( 'type' => 'string' ),
								),
								'required'   => array( 'name' ),
							),
						),
					),
					'required'   => array( 'abilities' ),
				),
				'permission_callback' => array( self::class, 'check_permission' ),
				'execute_callback'    => array( self::class, 'execute' ),
				'meta'                => array(
					'mcp'          => array( 'public' => true ),
					'show_in_rest' => true,
					'annotations'  => array(
						'readonly'    => true,
						'destructive' => false,
						'idempotent'  => true,
					),
				),
			)
		);
	}

	/**
	 * Check permissions for discovering abilities.
	 *
	 * Validates user capabilities and caller identity.
	 *
	 * @param array $input Input parameters (unused for this ability).
	 *
	 * @return bool|\WP_Error True if the user has permission to discover abilities.
	 * @phpstan-return bool|\WP_Error
	 */
	public static function check_permission( $input = array() ) {
		// Validate user authentication and capabilities
		return self::validate_user_access();
	}

	/**
	 * Validate user authentication and basic capabilities for discover abilities.
	 *
	 * @return bool|\WP_Error True if valid, WP_Error if validation fails.
	 */
	private static function validate_user_access() {
		// Verify caller identity - ensure user is authenticated
		if ( ! is_user_logged_in() ) {
			return new \WP_Error( 'authentication_required', 'User must be authenticated to access this ability' );
		}

		// Check basic capability requirement - allow customization via filter
		$required_capability = apply_filters( 'mcp_adapter_discover_abilities_capability', 'read' );
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
	 * Execute the discover abilities functionality.
	 *
	 * Enforces security checks and mcp.public filtering.
	 *
	 * @param array $input Input parameters (unused for this ability).
	 *
	 * @return array Array containing public MCP abilities.
	 */
	public static function execute( $input = array() ): array {
		// Enforce security checks before execution
		$permission_check = self::check_permission( $input );
		if ( is_wp_error( $permission_check ) ) {
			return array(
				'error' => $permission_check->get_error_message(),
			);
		}

		// Get all abilities and filter for publicly exposed ones.
		$abilities = wp_get_abilities();

		// Extract filter parameters.
		$filter_category   = $input['category'] ?? '';
		$filter_annotation = $input['annotation'] ?? '';
		$filter_search     = $input['search'] ?? '';

		// Lean defaults (#139). When the caller passes no `compact`, default it to
		// true — the unfiltered verbose dump is ~411KB on a large site and blows
		// past AI-client token caps. When BOTH `compact` and `limit` are absent,
		// also cap the page at 100 (reviewer-calibrated: compact alone is not a
		// size bound — fluent-crm compact ≈ 25KB; limit:200 ≈ 17KB once the
		// Knowledge-Layer steering is prepended). An explicit `compact` (true or
		// false) suppresses the auto-limit so power users keep full control;
		// `compact:false, limit:0` reproduces the legacy verbose unbounded dump.
		$compact_explicit = array_key_exists( 'compact', $input );
		$limit_explicit   = array_key_exists( 'limit', $input );

		$compact = $compact_explicit ? ! empty( $input['compact'] ) : true;

		if ( $limit_explicit ) {
			$limit = min( absint( $input['limit'] ), 200 );
		} elseif ( ! $compact_explicit ) {
			$limit = 100;
		} else {
			$limit = 0;
		}

		$offset = isset( $input['offset'] ) ? absint( $input['offset'] ) : 0;

		$ability_list     = array();
		$unfiltered_total = 0;
		$category_counts  = array();
		foreach ( $abilities as $ability ) {
			$ability_name = $ability->get_name();

			// Check if ability is publicly exposed via MCP.
			if ( ! self::is_ability_mcp_public( $ability ) ) {
				continue;
			}

			// Only discover abilities with type='tool' (default type).
			if ( self::get_ability_mcp_type( $ability ) !== 'tool' ) {
				continue;
			}

			// Unfiltered total = mcp.public + type=tool, before category/annotation/search.
			++$unfiltered_total;

			// Filter by category.
			if ( $filter_category && $ability->get_category() !== $filter_category ) {
				continue;
			}

			// Filter by annotation.
			$meta = $ability->get_meta();
			if ( $filter_annotation ) {
				$annotations = $meta['annotations'] ?? array();
				if ( 'readonly' === $filter_annotation && empty( $annotations['readonly'] ) ) {
					continue;
				}
				if ( 'destructive' === $filter_annotation && empty( $annotations['destructive'] ) ) {
					continue;
				}
			}

			// Filter by search keyword.
			if ( $filter_search ) {
				$haystack = strtolower( $ability_name . ' ' . $ability->get_label() . ' ' . $ability->get_description() );
				if ( strpos( $haystack, strtolower( $filter_search ) ) === false ) {
					continue;
				}
			}

			// Histogram over the filtered set, pre-pagination (cheap — already
			// in the loop). Uses the ability's registered category verbatim; the
			// bridge-side shared-prefix bucketing (surecart-ecommerce → surecart)
			// is a separate follow-up and intentionally not applied here.
			$slug                     = (string) $ability->get_category();
			$category_counts[ $slug ] = ( $category_counts[ $slug ] ?? 0 ) + 1;

			if ( $compact ) {
				$ability_list[] = array(
					'name'     => $ability_name,
					'category' => $ability->get_category(),
					'tier'     => $meta['tier'] ?? 'free',
				);
			} else {
				$ability_list[] = array(
					'name'        => $ability_name,
					'label'       => $ability->get_label(),
					'description' => $ability->get_description(),
					'category'    => $ability->get_category(),
					'tier'        => $meta['tier'] ?? 'free',
				);
			}
		}

		// Pagination — applied after filtering.
		$total_filtered = count( $ability_list );
		if ( $limit > 0 ) {
			$ability_list = array_slice( $ability_list, $offset, $limit );
		} elseif ( $offset > 0 ) {
			$ability_list = array_slice( $ability_list, $offset );
		}
		$returned    = count( $ability_list );
		$has_more    = ( $offset + $returned ) < $total_filtered;
		$next_offset = $has_more ? ( $offset + $returned ) : null;

		// Categories histogram over the filtered set (pre-pagination), sorted by
		// count desc then slug asc for stable ordering.
		$categories = array();
		foreach ( $category_counts as $slug => $count ) {
			$categories[] = array(
				'slug'  => $slug,
				'count' => $count,
			);
		}
		usort(
			$categories,
			static function ( $a, $b ) {
				if ( $a['count'] === $b['count'] ) {
					return strcmp( $a['slug'], $b['slug'] );
				}
				return $b['count'] - $a['count'];
			}
		);

		// Build response.
		$is_filtered = (bool) ( $filter_category || $filter_annotation || $filter_search );

		// If knowledge/boot exists, put the directive at the top of the response.
		$has_knowledge_boot = isset( $abilities['knowledge/boot'] );
		if ( $has_knowledge_boot ) {
			$response = array(
				'message'                          => 'This site has a Knowledge Layer. Before presenting abilities to the user, ask them which option they prefer.',
				'present_these_options_to_the_user' => array(
					array(
						'label'  => 'Boot the knowledge sequence',
						'action' => array( 'ability' => 'knowledge/boot' ),
					),
					array(
						'label'  => 'Tell me what we are doing in this session',
						'action' => 'ask_user',
					),
				),
			);
		} else {
			$response = array();
		}

		$response['abilities'] = $ability_list;
		$response['total']     = $total_filtered;
		$response['filtered']  = $is_filtered;

		// Pagination envelope — always present and self-documenting (#139).
		// `total` is the unfiltered mcp.public+tool count; `filtered_total` is the
		// post-filter count before paging. Renamed from the prior `_pagination`
		// (which was emitted only when a limit was set) — the underscore-prefixed
		// key is gone; no other reader referenced it.
		$response['pagination'] = array(
			'total'          => $unfiltered_total,
			'filtered_total' => $total_filtered,
			'returned'       => $returned,
			'offset'         => $offset,
			'next_offset'    => $next_offset,
			'has_more'       => $has_more,
			'compact'        => $compact,
		);

		// Always-present category histogram over the filtered set (#139).
		$response['categories'] = $categories;

		return $response;
	}
}
