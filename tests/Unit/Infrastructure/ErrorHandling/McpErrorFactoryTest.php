<?php

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Infrastructure\ErrorHandling;

use WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\McpErrorFactory;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class McpErrorFactoryTest extends TestCase {

	// ── Error code constants ──

	public function test_error_code_constants_have_expected_values(): void {
		$this->assertSame( -32700, McpErrorFactory::PARSE_ERROR );
		$this->assertSame( -32600, McpErrorFactory::INVALID_REQUEST );
		$this->assertSame( -32601, McpErrorFactory::METHOD_NOT_FOUND );
		$this->assertSame( -32602, McpErrorFactory::INVALID_PARAMS );
		$this->assertSame( -32603, McpErrorFactory::INTERNAL_ERROR );
		$this->assertSame( -32000, McpErrorFactory::SERVER_ERROR );
		$this->assertSame( -32001, McpErrorFactory::TIMEOUT_ERROR );
		$this->assertSame( -32002, McpErrorFactory::RESOURCE_NOT_FOUND );
		$this->assertSame( -32003, McpErrorFactory::TOOL_NOT_FOUND );
		$this->assertSame( -32004, McpErrorFactory::PROMPT_NOT_FOUND );
		$this->assertSame( -32008, McpErrorFactory::PERMISSION_DENIED );
		$this->assertSame( -32010, McpErrorFactory::UNAUTHORIZED );
	}

	// ── create_error_response() ──

	public function test_create_error_response_structure(): void {
		$response = McpErrorFactory::create_error_response( 1, -32600, 'Test error' );

		$this->assertSame( '2.0', $response['jsonrpc'] );
		$this->assertSame( 1, $response['id'] );
		$this->assertSame( -32600, $response['error']['code'] );
		$this->assertSame( 'Test error', $response['error']['message'] );
		$this->assertArrayNotHasKey( 'data', $response['error'] );
	}

	public function test_create_error_response_with_data(): void {
		$data     = array( 'field' => 'name' );
		$response = McpErrorFactory::create_error_response( 1, -32602, 'Invalid', $data );

		$this->assertSame( $data, $response['error']['data'] );
	}

	public function test_create_error_response_with_null_id(): void {
		$response = McpErrorFactory::create_error_response( null, -32700, 'Parse error' );

		$this->assertNull( $response['id'] );
	}

	public function test_create_error_response_with_string_id(): void {
		$response = McpErrorFactory::create_error_response( 'req-123', -32600, 'Error' );

		$this->assertSame( 'req-123', $response['id'] );
	}

	// ── parse_error() ──

	public function test_parse_error_without_details(): void {
		$response = McpErrorFactory::parse_error( 1 );

		$this->assertSame( McpErrorFactory::PARSE_ERROR, $response['error']['code'] );
		$this->assertSame( 'Parse error', $response['error']['message'] );
	}

	public function test_parse_error_with_details(): void {
		$response = McpErrorFactory::parse_error( 1, 'Unexpected token' );

		$this->assertStringContainsString( 'Unexpected token', $response['error']['message'] );
	}

	// ── invalid_request() ──

	public function test_invalid_request_without_details(): void {
		$response = McpErrorFactory::invalid_request( 2 );

		$this->assertSame( McpErrorFactory::INVALID_REQUEST, $response['error']['code'] );
		$this->assertSame( 'Invalid Request', $response['error']['message'] );
	}

	public function test_invalid_request_with_details(): void {
		$response = McpErrorFactory::invalid_request( 2, 'Missing jsonrpc field' );

		$this->assertStringContainsString( 'Missing jsonrpc field', $response['error']['message'] );
	}

	// ── method_not_found() ──

	public function test_method_not_found(): void {
		$response = McpErrorFactory::method_not_found( 3, 'tools/unknown' );

		$this->assertSame( McpErrorFactory::METHOD_NOT_FOUND, $response['error']['code'] );
		$this->assertStringContainsString( 'tools/unknown', $response['error']['message'] );
	}

	// ── invalid_params() ──

	public function test_invalid_params_without_details(): void {
		$response = McpErrorFactory::invalid_params( 4 );

		$this->assertSame( McpErrorFactory::INVALID_PARAMS, $response['error']['code'] );
		$this->assertSame( 'Invalid params', $response['error']['message'] );
	}

	public function test_invalid_params_with_details(): void {
		$response = McpErrorFactory::invalid_params( 4, 'name is required' );

		$this->assertStringContainsString( 'name is required', $response['error']['message'] );
	}

	// ── internal_error() ──

	public function test_internal_error_without_details(): void {
		$response = McpErrorFactory::internal_error( 5 );

		$this->assertSame( McpErrorFactory::INTERNAL_ERROR, $response['error']['code'] );
		$this->assertSame( 'Internal error', $response['error']['message'] );
	}

	public function test_internal_error_with_details(): void {
		$response = McpErrorFactory::internal_error( 5, 'Database connection failed' );

		$this->assertStringContainsString( 'Database connection failed', $response['error']['message'] );
	}

	// ── mcp_disabled() ──

	public function test_mcp_disabled(): void {
		$response = McpErrorFactory::mcp_disabled( 6 );

		$this->assertSame( McpErrorFactory::SERVER_ERROR, $response['error']['code'] );
		$this->assertStringContainsString( 'disabled', $response['error']['message'] );
	}

	// ── validation_error() ──

	public function test_validation_error(): void {
		$response = McpErrorFactory::validation_error( 7, 'name too long' );

		$this->assertSame( McpErrorFactory::INVALID_PARAMS, $response['error']['code'] );
		$this->assertStringContainsString( 'name too long', $response['error']['message'] );
	}

	// ── missing_parameter() ──

	public function test_missing_parameter(): void {
		$response = McpErrorFactory::missing_parameter( 8, 'uri' );

		$this->assertSame( McpErrorFactory::INVALID_PARAMS, $response['error']['code'] );
		$this->assertStringContainsString( 'uri', $response['error']['message'] );
	}

	// ── resource_not_found() ──

	public function test_resource_not_found(): void {
		$response = McpErrorFactory::resource_not_found( 9, 'file:///missing' );

		$this->assertSame( McpErrorFactory::RESOURCE_NOT_FOUND, $response['error']['code'] );
		$this->assertStringContainsString( 'file:///missing', $response['error']['message'] );
	}

	// ── tool_not_found() ──

	public function test_tool_not_found(): void {
		$response = McpErrorFactory::tool_not_found( 10, 'unknown-tool' );

		$this->assertSame( McpErrorFactory::TOOL_NOT_FOUND, $response['error']['code'] );
		$this->assertStringContainsString( 'unknown-tool', $response['error']['message'] );
	}

	// ── ability_not_found() ──

	public function test_ability_not_found(): void {
		$response = McpErrorFactory::ability_not_found( 11, 'content/missing' );

		$this->assertSame( McpErrorFactory::TOOL_NOT_FOUND, $response['error']['code'] );
		$this->assertStringContainsString( 'content/missing', $response['error']['message'] );
	}

	// ── prompt_not_found() ──

	public function test_prompt_not_found(): void {
		$response = McpErrorFactory::prompt_not_found( 12, 'unknown-prompt' );

		$this->assertSame( McpErrorFactory::PROMPT_NOT_FOUND, $response['error']['code'] );
		$this->assertStringContainsString( 'unknown-prompt', $response['error']['message'] );
	}

	// ── permission_denied() ──

	public function test_permission_denied_without_details(): void {
		$response = McpErrorFactory::permission_denied( 13 );

		$this->assertSame( McpErrorFactory::PERMISSION_DENIED, $response['error']['code'] );
		$this->assertSame( 'Permission denied', $response['error']['message'] );
	}

	public function test_permission_denied_with_details(): void {
		$response = McpErrorFactory::permission_denied( 13, 'Requires admin' );

		$this->assertStringContainsString( 'Requires admin', $response['error']['message'] );
	}

	// ── unauthorized() ──

	public function test_unauthorized_without_details(): void {
		$response = McpErrorFactory::unauthorized( 14 );

		$this->assertSame( McpErrorFactory::UNAUTHORIZED, $response['error']['code'] );
		$this->assertSame( 'Unauthorized', $response['error']['message'] );
	}

	public function test_unauthorized_with_details(): void {
		$response = McpErrorFactory::unauthorized( 14, 'Token expired' );

		$this->assertStringContainsString( 'Token expired', $response['error']['message'] );
	}

	// ── mcp_error_to_http_status() ──

	public function test_parse_error_maps_to_400(): void {
		$this->assertSame( 400, McpErrorFactory::mcp_error_to_http_status( McpErrorFactory::PARSE_ERROR ) );
	}

	public function test_invalid_request_maps_to_400(): void {
		$this->assertSame( 400, McpErrorFactory::mcp_error_to_http_status( McpErrorFactory::INVALID_REQUEST ) );
	}

	public function test_unauthorized_maps_to_401(): void {
		$this->assertSame( 401, McpErrorFactory::mcp_error_to_http_status( McpErrorFactory::UNAUTHORIZED ) );
	}

	public function test_permission_denied_maps_to_403(): void {
		$this->assertSame( 403, McpErrorFactory::mcp_error_to_http_status( McpErrorFactory::PERMISSION_DENIED ) );
	}

	public function test_not_found_errors_map_to_404(): void {
		$this->assertSame( 404, McpErrorFactory::mcp_error_to_http_status( McpErrorFactory::RESOURCE_NOT_FOUND ) );
		$this->assertSame( 404, McpErrorFactory::mcp_error_to_http_status( McpErrorFactory::TOOL_NOT_FOUND ) );
		$this->assertSame( 404, McpErrorFactory::mcp_error_to_http_status( McpErrorFactory::PROMPT_NOT_FOUND ) );
		$this->assertSame( 404, McpErrorFactory::mcp_error_to_http_status( McpErrorFactory::METHOD_NOT_FOUND ) );
	}

	public function test_server_errors_map_to_500(): void {
		$this->assertSame( 500, McpErrorFactory::mcp_error_to_http_status( McpErrorFactory::INTERNAL_ERROR ) );
		$this->assertSame( 500, McpErrorFactory::mcp_error_to_http_status( McpErrorFactory::SERVER_ERROR ) );
	}

	public function test_timeout_maps_to_504(): void {
		$this->assertSame( 504, McpErrorFactory::mcp_error_to_http_status( McpErrorFactory::TIMEOUT_ERROR ) );
	}

	public function test_invalid_params_maps_to_200(): void {
		$this->assertSame( 200, McpErrorFactory::mcp_error_to_http_status( McpErrorFactory::INVALID_PARAMS ) );
	}

	public function test_unknown_code_maps_to_200(): void {
		$this->assertSame( 200, McpErrorFactory::mcp_error_to_http_status( -99999 ) );
	}

	// ── get_http_status_for_error() ──

	public function test_get_http_status_for_error_extracts_code(): void {
		$error  = McpErrorFactory::parse_error( 1 );
		$status = McpErrorFactory::get_http_status_for_error( $error );

		$this->assertSame( 400, $status );
	}

	public function test_get_http_status_for_error_missing_code_returns_500(): void {
		$status = McpErrorFactory::get_http_status_for_error( array() );

		$this->assertSame( 500, $status );
	}

	// ── validate_jsonrpc_message() ──

	public function test_valid_request_message(): void {
		$message = array(
			'jsonrpc' => '2.0',
			'id'      => 1,
			'method'  => 'tools/list',
		);
		$this->assertTrue( McpErrorFactory::validate_jsonrpc_message( $message ) );
	}

	public function test_valid_notification_message(): void {
		$message = array(
			'jsonrpc' => '2.0',
			'method'  => 'notifications/initialized',
		);
		$this->assertTrue( McpErrorFactory::validate_jsonrpc_message( $message ) );
	}

	public function test_valid_response_message(): void {
		$message = array(
			'jsonrpc' => '2.0',
			'id'      => 1,
			'result'  => array(),
		);
		$this->assertTrue( McpErrorFactory::validate_jsonrpc_message( $message ) );
	}

	public function test_non_array_message_returns_error(): void {
		$result = McpErrorFactory::validate_jsonrpc_message( 'not-an-array' );
		$this->assertIsArray( $result );
		$this->assertArrayHasKey( 'error', $result );
	}

	public function test_missing_jsonrpc_field_returns_error(): void {
		$result = McpErrorFactory::validate_jsonrpc_message( array( 'method' => 'test' ) );
		$this->assertIsArray( $result );
	}

	public function test_wrong_jsonrpc_version_returns_error(): void {
		$result = McpErrorFactory::validate_jsonrpc_message( array( 'jsonrpc' => '1.0', 'method' => 'test' ) );
		$this->assertIsArray( $result );
	}

	public function test_message_without_method_or_result_returns_error(): void {
		$result = McpErrorFactory::validate_jsonrpc_message( array( 'jsonrpc' => '2.0', 'id' => 1 ) );
		$this->assertIsArray( $result );
	}

	public function test_response_without_id_returns_error(): void {
		$result = McpErrorFactory::validate_jsonrpc_message( array( 'jsonrpc' => '2.0', 'result' => array() ) );
		$this->assertIsArray( $result );
	}
}
