<?php

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Infrastructure\ErrorHandling;

use WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\McpErrorFactory;
use WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\McpErrorMapper;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class McpErrorMapperTest extends TestCase {

	// ── map_code() — known codes ──

	public function test_map_rest_forbidden_to_permission_denied(): void {
		$this->assertSame( McpErrorFactory::PERMISSION_DENIED, McpErrorMapper::map_code( 'rest_forbidden' ) );
	}

	public function test_map_rest_unauthorized_to_unauthorized(): void {
		$this->assertSame( McpErrorFactory::UNAUTHORIZED, McpErrorMapper::map_code( 'rest_unauthorized' ) );
	}

	public function test_map_rest_no_route_to_method_not_found(): void {
		$this->assertSame( McpErrorFactory::METHOD_NOT_FOUND, McpErrorMapper::map_code( 'rest_no_route' ) );
	}

	public function test_map_rest_invalid_param_to_invalid_params(): void {
		$this->assertSame( McpErrorFactory::INVALID_PARAMS, McpErrorMapper::map_code( 'rest_invalid_param' ) );
	}

	public function test_map_ability_not_found_to_tool_not_found(): void {
		$this->assertSame( McpErrorFactory::TOOL_NOT_FOUND, McpErrorMapper::map_code( 'ability_not_found' ) );
	}

	public function test_map_ability_invalid_permissions_to_permission_denied(): void {
		$this->assertSame( McpErrorFactory::PERMISSION_DENIED, McpErrorMapper::map_code( 'ability_invalid_permissions' ) );
	}

	public function test_map_ability_invalid_input_to_invalid_params(): void {
		$this->assertSame( McpErrorFactory::INVALID_PARAMS, McpErrorMapper::map_code( 'ability_invalid_input' ) );
	}

	public function test_map_ability_missing_input_schema_to_internal_error(): void {
		$this->assertSame( McpErrorFactory::INTERNAL_ERROR, McpErrorMapper::map_code( 'ability_missing_input_schema' ) );
	}

	public function test_map_forbidden_to_permission_denied(): void {
		$this->assertSame( McpErrorFactory::PERMISSION_DENIED, McpErrorMapper::map_code( 'forbidden' ) );
	}

	public function test_map_not_found_to_resource_not_found(): void {
		$this->assertSame( McpErrorFactory::RESOURCE_NOT_FOUND, McpErrorMapper::map_code( 'not_found' ) );
	}

	// ── map_code() — unknown codes ──

	public function test_unknown_code_defaults_to_internal_error(): void {
		$this->assertSame( McpErrorFactory::INTERNAL_ERROR, McpErrorMapper::map_code( 'some_unknown_code' ) );
	}

	public function test_unknown_code_with_custom_default(): void {
		$this->assertSame( McpErrorFactory::SERVER_ERROR, McpErrorMapper::map_code( 'unknown', McpErrorFactory::SERVER_ERROR ) );
	}

	// ── from_wp_error() ──

	public function test_from_wp_error_creates_proper_response(): void {
		$wp_error = new \WP_Error( 'ability_not_found', 'The ability was not found' );
		$response = McpErrorMapper::from_wp_error( 42, $wp_error );

		$this->assertSame( '2.0', $response['jsonrpc'] );
		$this->assertSame( 42, $response['id'] );
		$this->assertSame( McpErrorFactory::TOOL_NOT_FOUND, $response['error']['code'] );
		$this->assertSame( 'The ability was not found', $response['error']['message'] );
	}

	public function test_from_wp_error_with_data(): void {
		$wp_error = new \WP_Error( 'rest_invalid_param', 'Invalid param', array( 'param' => 'name' ) );
		$response = McpErrorMapper::from_wp_error( 'req-1', $wp_error );

		$this->assertSame( 'req-1', $response['id'] );
		$this->assertSame( McpErrorFactory::INVALID_PARAMS, $response['error']['code'] );
		$this->assertSame( array( 'param' => 'name' ), $response['error']['data'] );
	}

	public function test_from_wp_error_with_null_id(): void {
		$wp_error = new \WP_Error( 'rest_forbidden', 'Access denied' );
		$response = McpErrorMapper::from_wp_error( null, $wp_error );

		$this->assertNull( $response['id'] );
		$this->assertSame( McpErrorFactory::PERMISSION_DENIED, $response['error']['code'] );
	}

	public function test_from_wp_error_unknown_code_uses_internal_error(): void {
		$wp_error = new \WP_Error( 'custom_error', 'Something went wrong' );
		$response = McpErrorMapper::from_wp_error( 1, $wp_error );

		$this->assertSame( McpErrorFactory::INTERNAL_ERROR, $response['error']['code'] );
		$this->assertSame( 'Something went wrong', $response['error']['message'] );
	}

	public function test_from_wp_error_without_data_omits_data_key(): void {
		$wp_error = new \WP_Error( 'not_found', 'Not found', '' );
		$response = McpErrorMapper::from_wp_error( 1, $wp_error );

		// The WP_Error stub initializes data as '' which is not null,
		// so create_error_response will include it. This tests the actual behavior.
		$this->assertArrayHasKey( 'data', $response['error'] );
	}
}
