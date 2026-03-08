<?php
/**
 * Utility class for mapping WordPress errors to MCP error codes and messages.
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling;

/**
 * Utility class for mapping WordPress errors to MCP error codes and messages.
 *
 * This class provides centralized logic for converting WP_Error objects and
 * internal error codes into standardized MCP error formats.
 */
class McpErrorMapper {

	/**
	 * Map of WordPress error codes to MCP error codes.
	 *
	 * @var array<string, int>
	 */
	private static array $error_code_map = array(
		'rest_forbidden'               => McpErrorFactory::PERMISSION_DENIED,
		'rest_unauthorized'            => McpErrorFactory::UNAUTHORIZED,
		'rest_no_route'                => McpErrorFactory::METHOD_NOT_FOUND,
		'rest_invalid_param'           => McpErrorFactory::INVALID_PARAMS,
		'ability_not_found'            => McpErrorFactory::TOOL_NOT_FOUND,
		'ability_invalid_permissions'  => McpErrorFactory::PERMISSION_DENIED,
		'ability_invalid_input'        => McpErrorFactory::INVALID_PARAMS,
		'ability_missing_input_schema' => McpErrorFactory::INTERNAL_ERROR,
		'forbidden'                    => McpErrorFactory::PERMISSION_DENIED,
		'not_found'                    => McpErrorFactory::RESOURCE_NOT_FOUND,
	);

	/**
	 * Map a WordPress error code to an MCP error code.
	 *
	 * @param string $wp_error_code The WordPress error code.
	 * @param int    $default_code  The default MCP code if no mapping is found.
	 *
	 * @return int The mapped MCP error code.
	 */
	public static function map_code( string $wp_error_code, int $default_code = McpErrorFactory::INTERNAL_ERROR ): int {
		return self::$error_code_map[ $wp_error_code ] ?? $default_code;
	}

	/**
	 * Create an MCP error response from a WP_Error object.
	 *
	 * @param mixed     $request_id The request ID.
	 * @param \WP_Error $wp_error   The WordPress error object.
	 *
	 * @return array The MCP error response.
	 */
	public static function from_wp_error( $request_id, \WP_Error $wp_error ): array {
		$code    = self::map_code( $wp_error->get_error_code() );
		$message = $wp_error->get_error_message();
		$data    = $wp_error->get_error_data();

		return McpErrorFactory::create_error_response( $request_id, $code, $message, $data );
	}
}
