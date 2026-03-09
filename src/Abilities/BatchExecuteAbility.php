<?php
/**
 * Ability for executing multiple MCP tools in a single request.
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Abilities;

use WickedEvolutions\McpAdapter\Core\McpAdapter;
use WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\McpErrorFactory;

/**
 * Batch Execute - Executes multiple MCP tools in a single request.
 *
 * This ability allows for optimized batch processing by reducing the number
 * of round-trips between the client/bridge and the WordPress server.
 */
final class BatchExecuteAbility {
	use McpAbilityHelperTrait;

	/**
	 * Register the ability.
	 */
	public static function register(): void {
		wp_register_ability(
			'mcp-adapter/batch-execute',
			array(
				'label'               => 'Batch Execute Tools',
				'description'         => 'Execute multiple MCP tools in a single round-trip. Returns an array of results in the same order.',
				'category'            => 'mcp-adapter',
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'requests' => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'name'      => array( 'type' => 'string', 'description' => 'The tool name to call' ),
									'arguments' => array( 'type' => 'object', 'description' => 'Arguments for the tool' ),
								),
								'required'   => array( 'name' ),
							),
							'minItems' => 1,
							'maxItems' => 20,
						),
					),
					'required'   => array( 'requests' ),
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'results' => array(
							'type'  => 'array',
							'items' => array( 'type' => 'object' ),
						),
					),
					'required'   => array( 'results' ),
				),
				'permission_callback' => array( self::class, 'check_permission' ),
				'execute_callback'    => array( self::class, 'execute' ),
				'meta'                => array(
					'annotations' => array(
						'readonly'    => false,
						'destructive' => true,
						'idempotent'  => false,
					),
				),
			)
		);
	}

	/**
	 * Check permissions for batch execution.
	 *
	 * @param array $input Input parameters.
	 * @return bool|\WP_Error
	 */
	public static function check_permission( $input = array() ) {
		if ( ! is_user_logged_in() ) {
			return new \WP_Error( 'authentication_required', 'User must be authenticated' );
		}
		
		// Batch execute itself requires manage_options by default for safety.
		return current_user_can( 'manage_options' );
	}

	/**
	 * Execute the batch tools functionality.
	 *
	 * @param array $input Input parameters containing 'requests'.
	 * @return array Array containing results for each request.
	 */
	public static function execute( $input = array() ): array {
		$requests = $input['requests'] ?? array();
		$results  = array();

		// Resolve the first registered server — avoids hardcoded ID assumption.
		$adapter = McpAdapter::instance();
		$servers = $adapter->get_servers();

		if ( empty( $servers ) ) {
			return array(
				'results' => array(
					array(
						'content' => array( array( 'type' => 'text', 'text' => 'No MCP server registered' ) ),
						'isError' => true,
					),
				),
			);
		}

		$server  = reset( $servers );
		$handler = new \WickedEvolutions\McpAdapter\Handlers\Tools\ToolsHandler( $server );

		foreach ( $requests as $request ) {
			$tool_name = $request['name'] ?? '';
			$args      = $request['arguments'] ?? array();

			$message = array(
				'method' => 'tools/call',
				'params' => array(
					'name'      => $tool_name,
					'arguments' => $args,
				),
			);

			try {
				$raw = $handler->call_tool( $message );
			} catch ( \Throwable $e ) {
				$results[] = array(
					'content' => array( array( 'type' => 'text', 'text' => $e->getMessage() ) ),
					'isError' => true,
				);
				continue;
			}

			// Strip internal _metadata — not part of the wire format.
			unset( $raw['_metadata'] );

			// Protocol errors (not_found, etc.) come back as {error: {...}} — convert to isError wire format.
			if ( isset( $raw['error'] ) ) {
				$error_message = $raw['error']['message'] ?? 'Tool call failed';
				$results[] = array(
					'content' => array( array( 'type' => 'text', 'text' => $error_message ) ),
					'isError' => true,
				);
				continue;
			}

			// Normal wire format: {content: [...], isError?: false, structuredContent?: {...}}
			$results[] = $raw;
		}

		return array(
			'results' => $results,
		);
	}
}
