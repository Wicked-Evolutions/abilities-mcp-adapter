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

		// We need access to the ToolsHandler to process individual calls.
		// Since we're inside an ability, we can assume the McpAdapter is initialized.
		$adapter = McpAdapter::instance();
		$server  = $adapter->get_server( 'mcp-adapter-default-server' );

		if ( ! $server ) {
			return array( 'error' => 'Default MCP server not found' );
		}

		$handler = new \WickedEvolutions\McpAdapter\Handlers\Tools\ToolsHandler( $server );

		foreach ( $requests as $request ) {
			$tool_name = $request['name'];
			$args      = $request['arguments'] ?? array();

			// Prepare the message in the format expected by call_tool
			$message = array(
				'method' => 'tools/call',
				'params' => array(
					'name'      => $tool_name,
					'arguments' => $args,
				),
			);

			// Execute the tool call
			$response = $handler->call_tool( $message );
			$results[] = $response;
		}

		return array(
			'results' => $results,
		);
	}
}
