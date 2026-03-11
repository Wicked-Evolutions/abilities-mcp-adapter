<?php
/**
 * MCP Annotation Mapper utility class for mapping WordPress ability annotations to MCP format.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Domain\Utils;

use WickedEvolutions\McpAdapter\Admin\PermissionManager;

/**
 * Utility class for mapping WordPress ability annotations to MCP Annotations format.
 *
 * Provides shared annotation mapping and transformation logic used across multiple
 * MCP component registration classes. Handles conversion of WordPress-format annotations
 * to MCP-compliant annotation structures.
 */
class McpAnnotationMapper {

	/**
	 * Comprehensive mapping of MCP annotations.
	 *
	 * Maps MCP annotation fields to their type, which features they apply to,
	 * and their WordPress Ability API equivalent property names.
	 *
	 * Structure:
	 * - type: The data type (boolean, string, array, number)
	 * - features: Array of MCP features where this annotation is used (tool, resource, prompt)
	 * - ability_property: The WordPress Ability API property name (may differ from MCP field name), or null if mapping 1:1
	 *
	 * @var array<string, array{type: string, features: array<string>, ability_property: string|null}>
	 */
	private static array $mcp_annotations = array(
		// Shared annotations (all features) - in annotations object.
		'audience'        => array(
			'type'             => 'array',
			'features'         => array( 'tool', 'resource', 'prompt' ),
			'ability_property' => null,
		),
		'lastModified'    => array(
			'type'             => 'string',
			'features'         => array( 'tool', 'resource', 'prompt' ),
			'ability_property' => null,
		),
		'priority'        => array(
			'type'             => 'number',
			'features'         => array( 'tool', 'resource', 'prompt' ),
			'ability_property' => null,
		),
		'readOnlyHint'    => array(
			'type'             => 'boolean',
			'features'         => array( 'tool' ),
			'ability_property' => 'readonly',
		),
		'destructiveHint' => array(
			'type'             => 'boolean',
			'features'         => array( 'tool' ),
			'ability_property' => 'destructive',
		),
		'idempotentHint'  => array(
			'type'             => 'boolean',
			'features'         => array( 'tool' ),
			'ability_property' => 'idempotent',
		),
		'category'        => array(
			'type'             => 'string',
			'features'         => array( 'tool', 'resource', 'prompt' ),
			'ability_property' => 'category',
		),
		'tier'            => array(
			'type'             => 'string',
			'features'         => array( 'tool', 'resource', 'prompt' ),
			'ability_property' => 'tier',
		),
		'bridgeHints'     => array(
			'type'             => 'array',
			'features'         => array( 'tool', 'resource', 'prompt' ),
			'ability_property' => 'bridge_hints',
		),
		'openWorldHint'   => array(
			'type'             => 'boolean',
			'features'         => array( 'tool' ),
			'ability_property' => null,
		),
		'title'           => array(
			'type'             => 'string',
			'features'         => array( 'tool' ),
			'ability_property' => null,
		),
		'permission'      => array(
			'type'             => 'string',
			'features'         => array( 'tool', 'resource', 'prompt' ),
			'ability_property' => 'permission',
		),
		'enabled'         => array(
			'type'             => 'boolean',
			'features'         => array( 'tool', 'resource', 'prompt' ),
			'ability_property' => 'enabled',
		),
	);

	/**
	 * Build MCP annotations from a WordPress ability.
	 *
	 * Consolidates the annotation injection logic previously duplicated in
	 * RegisterAbilityAsMcpTool, RegisterAbilityAsMcpResource, and RegisterAbilityAsMcpPrompt.
	 *
	 * Injects: category, tier, bridge_hints, permission, enabled.
	 *
	 * @param \WP_Ability $ability      The WordPress ability.
	 * @param string      $feature_type The MCP feature type ('tool', 'resource', or 'prompt').
	 *
	 * @return array Mapped MCP annotations, or empty array if none.
	 */
	public static function build_from_ability( \WP_Ability $ability, string $feature_type ): array {
		$ability_meta = $ability->get_meta();
		$annotations  = $ability_meta['annotations'] ?? array();

		// Inject top-level category if not explicitly set in annotations.
		if ( ! isset( $annotations['category'] ) ) {
			$annotations['category'] = $ability->get_category();
		}

		// Inject tier from meta if not explicitly set in annotations.
		if ( ! isset( $annotations['tier'] ) && isset( $ability_meta['tier'] ) ) {
			$annotations['tier'] = $ability_meta['tier'];
		}

		// Inject bridge_hints from meta if not explicitly set in annotations.
		if ( ! isset( $annotations['bridge_hints'] ) && isset( $ability_meta['bridge_hints'] ) ) {
			$annotations['bridge_hints'] = $ability_meta['bridge_hints'];
		}

		// Inject permission level derived from annotations or explicit metadata.
		$annotations['permission'] = PermissionManager::get_permission( $ability );

		// Inject enabled state from admin settings.
		$annotations['enabled'] = PermissionManager::is_enabled( $ability->get_name() );

		if ( empty( $annotations ) || ! is_array( $annotations ) ) {
			return array();
		}

		return self::map( $annotations, $feature_type );
	}

	/**
	 * Map WordPress ability annotation property names to MCP field names.
	 *
	 * Maps WordPress-format field names to MCP equivalents (e.g., readonly → readOnlyHint).
	 * Only includes annotations applicable to the specified feature type.
	 * Null values are excluded from the result.
	 *
	 * @param array  $ability_annotations WordPress ability annotations.
	 * @param string $feature_type        The MCP feature type ('tool', 'resource', or 'prompt').
	 *
	 * @return array Mapped annotations for the specified feature type.
	 */
	public static function map( array $ability_annotations, string $feature_type ): array {
		$result = array();

		foreach ( self::$mcp_annotations as $mcp_field => $config ) {
			if ( ! in_array( $feature_type, $config['features'], true ) ) {
				continue;
			}

			$value = self::resolve_annotation_value(
				$ability_annotations,
				$mcp_field,
				$config['ability_property']
			);

			if ( null === $value ) {
				continue;
			}

			$normalized = self::normalize_annotation_value( $config['type'], $value );
			if ( null === $normalized ) {
				continue;
			}

			$result[ $mcp_field ] = $normalized;
		}

		return $result;
	}

	/**
	 * Resolve the annotation value, preferring WordPress-format overrides when available.
	 *
	 * @param array       $annotations     Raw annotations from the ability.
	 * @param string      $mcp_field       The MCP field name.
	 * @param string|null $ability_property Optional WordPress-format field name, or null if mapping 1:1.
	 *
	 * @return mixed The annotation value, or null if not found.
	 */
	private static function resolve_annotation_value( array $annotations, string $mcp_field, ?string $ability_property ) {
		// WordPress-format overrides take precedence when present.
		if ( null !== $ability_property && array_key_exists( $ability_property, $annotations ) && ! is_null( $annotations[ $ability_property ] ) ) {
			return $annotations[ $ability_property ];
		}

		if ( array_key_exists( $mcp_field, $annotations ) && ! is_null( $annotations[ $mcp_field ] ) ) {
			return $annotations[ $mcp_field ];
		}

		return null;
	}

	/**
	 * Normalize annotation values to the types expected by MCP.
	 *
	 * @param string $field_type Expected MCP type (boolean, string, array, number).
	 * @param mixed  $value      Raw annotation value.
	 *
	 * @return mixed|null Normalized value or null if invalid.
	 */
	private static function normalize_annotation_value( string $field_type, $value ) {
		switch ( $field_type ) {
			case 'boolean':
				return (bool) $value;

			case 'string':
				if ( ! is_scalar( $value ) ) {
					return null;
				}
				$trimmed = trim( (string) $value );
				return '' === $trimmed ? null : $trimmed;

			case 'array':
				return is_array( $value ) && ! empty( $value ) ? $value : null;

			case 'number':
				return is_numeric( $value ) ? (float) $value : null;

			default:
				return $value;
		}
	}
}
