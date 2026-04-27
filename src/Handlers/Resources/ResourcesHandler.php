<?php
/**
 * Resources method handlers for MCP requests.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Handlers\Resources;

use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthScopeEnforcer;
use WickedEvolutions\McpAdapter\Core\McpServer;
use WickedEvolutions\McpAdapter\Handlers\HandlerHelperTrait;
use WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\McpErrorFactory;

/**
 * Handles resources-related MCP methods.
 */
class ResourcesHandler {
	use HandlerHelperTrait;

	/**
	 * The WordPress MCP instance.
	 *
	 * @var \WickedEvolutions\McpAdapter\Core\McpServer
	 */
	private McpServer $mcp;

	/**
	 * Constructor.
	 *
	 * @param \WickedEvolutions\McpAdapter\Core\McpServer $mcp The WordPress MCP instance.
	 */
	public function __construct( McpServer $mcp ) {
		$this->mcp = $mcp;
	}


	/**
	 * Handles the resources/list request.
	 *
	 * @param mixed $request_id Optional. The request ID for JSON-RPC (string, int, or null). Default 0.
	 *
	 * @return array Response with resources list and metadata.
	 */
	public function list_resources( $request_id = 0 ): array {
		// Get the registered resources from the MCP instance and extract only the args.
		$resources = array();
		foreach ( $this->mcp->get_resources() as $resource ) {
			// Strip content fields from the listing — content is deferred to resources/read.
			// Exposing text/blob here would leak data without per-resource permission checks.
			$descriptor = $resource->to_array();
			unset( $descriptor['text'], $descriptor['blob'] );
			$resources[] = $descriptor;
		}

		return array(
			'resources' => $resources,
			'_metadata' => array(
				'component_type'  => 'resources',
				'resources_count' => count( $resources ),
			),
		);
	}

	/**
	 * Handles the resources/read request.
	 *
	 * @param array $params     Request parameters.
	 * @param mixed $request_id Optional. The request ID for JSON-RPC (string, int, or null). Default 0.
	 *
	 * @return array Response with resource contents or error.
	 */
	public function read_resource( array $params, $request_id = 0 ): array {
		// Extract parameters using helper method.
		$request_params = $this->extract_params( $params );

		if ( ! isset( $request_params['uri'] ) ) {
			return array(
				'error'     => McpErrorFactory::missing_parameter( $request_id, 'uri' )['error'],
				'_metadata' => array(
					'component_type' => 'resource',
					'failure_reason' => 'missing_parameter',
				),
			);
		}

		// Implement resource reading logic here.
		$uri      = $request_params['uri'];
		$resource = $this->mcp->get_resource( $uri );

		if ( ! $resource ) {
			return array(
				'error'     => McpErrorFactory::resource_not_found( $request_id, $uri )['error'],
				'_metadata' => array(
					'component_type' => 'resource',
					'resource_uri'   => $uri,
					'failure_reason' => 'not_found',
				),
			);
		}

		/**
		 * Get the ability
		 *
		 * @var \WP_Ability|\WP_Error $ability
		 */
		$ability = $resource->get_ability();

		// Check if getting the ability returned an error
		if ( is_wp_error( $ability ) ) {
			$this->mcp->error_handler->log(
				'Failed to get ability for resource',
				array(
					'resource_uri'  => $uri,
					'error_message' => $ability->get_error_message(),
				)
			);

			return array(
				'error'     => McpErrorFactory::internal_error( $request_id )['error'],
				'_metadata' => array(
					'component_type' => 'resource',
					'resource_uri'   => $uri,
					'resource_name'  => $resource->get_name(),
					'failure_reason' => 'ability_retrieval_failed',
					'error_code'     => $ability->get_error_code(),
				),
			);
		}

		try {
			$has_permission = $ability->check_permissions();
			if ( true !== $has_permission ) {
				// Log detailed reason internally; never expose to client.
				$failure_reason = 'permission_denied';

				if ( is_wp_error( $has_permission ) ) {
					$failure_reason = $has_permission->get_error_code();
					$this->mcp->error_handler->log(
						'Permission denied for resource: ' . $has_permission->get_error_message(),
						array(
							'resource_uri' => $uri,
							'ability'      => $ability->get_name(),
						)
					);
				}

				return array(
					'error'     => McpErrorFactory::permission_denied( $request_id )['error'],
					'_metadata' => array(
						'component_type' => 'resource',
						'resource_uri'   => $uri,
						'resource_name'  => $resource->get_name(),
						'ability_name'   => $ability->get_name(),
						'failure_reason' => $failure_reason,
					),
				);
			}

			// OAuth scope gate (H.1.3 / #45). No-op for non-OAuth requests.
			$scope_denial = OAuthScopeEnforcer::check( $ability );
			if ( null !== $scope_denial ) {
				return array(
					'error'     => array(
						'code'    => McpErrorFactory::PERMISSION_DENIED,
						'message' => $scope_denial['message'],
						'data'    => array(
							'error'          => $scope_denial['error_code'],
							'required_scope' => $scope_denial['required_scope'],
						),
					),
					'_metadata' => array(
						'component_type' => 'resource',
						'resource_uri'   => $uri,
						'resource_name'  => $resource->get_name(),
						'ability_name'   => $ability->get_name(),
						'failure_reason' => 'insufficient_scope',
						'error_code'     => $scope_denial['required_scope'],
					),
				);
			}

			$contents = $ability->execute();

			// Handle WP_Error objects that weren't converted by the ability.
			if ( is_wp_error( $contents ) ) {
				$this->mcp->error_handler->log(
					'Ability returned WP_Error object',
					array(
						'ability'       => $ability->get_name(),
						'error_code'    => $contents->get_error_code(),
						'error_message' => $contents->get_error_message(),
					)
				);

				return array(
					'error'     => McpErrorFactory::internal_error( $request_id )['error'],
					'_metadata' => array(
						'component_type' => 'resource',
						'resource_uri'   => $uri,
						'resource_name'  => $resource->get_name(),
						'ability_name'   => $ability->get_name(),
						'failure_reason' => 'wp_error',
						'error_code'     => $contents->get_error_code(),
					),
				);
			}

			// Successful execution - return contents.
			return array(
				'contents'  => $contents,
				'_metadata' => array(
					'component_type' => 'resource',
					'resource_uri'   => $uri,
					'resource_name'  => $resource->get_name(),
					'ability_name'   => $ability->get_name(),
				),
			);
		} catch ( \Throwable $exception ) {
			$this->mcp->error_handler->log(
				'Error reading resource',
				array(
					'uri'       => $uri,
					'exception' => $exception->getMessage(),
				)
			);

			return array(
				'error'     => McpErrorFactory::internal_error( $request_id, 'Failed to read resource' )['error'],
				'_metadata' => array(
					'component_type' => 'resource',
					'resource_uri'   => $uri,
					'failure_reason' => 'execution_failed',
					'error_type'     => get_class( $exception ),
				),
			);
		}
	}
}
