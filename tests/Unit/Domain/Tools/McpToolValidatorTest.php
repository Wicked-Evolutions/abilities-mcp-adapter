<?php

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Domain\Tools;

use WickedEvolutions\McpAdapter\Domain\Tools\McpToolValidator;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class McpToolValidatorTest extends TestCase {

	/**
	 * Build a minimal valid tool data array.
	 */
	private function valid_tool_data(): array {
		return array(
			'name'        => 'my-tool',
			'description' => 'A test tool',
			'inputSchema' => array(
				'type'       => 'object',
				'properties' => array(
					'query' => array( 'type' => 'string' ),
				),
			),
		);
	}

	// ── validate_tool_data() — valid ──

	public function test_valid_tool_data_returns_true(): void {
		$result = McpToolValidator::validate_tool_data( $this->valid_tool_data() );
		$this->assertTrue( $result );
	}

	public function test_valid_tool_with_empty_schema_returns_true(): void {
		$data = array(
			'name'        => 'no-args-tool',
			'description' => 'Tool with no arguments',
			'inputSchema' => array(),
		);
		$result = McpToolValidator::validate_tool_data( $data );
		$this->assertTrue( $result );
	}

	// ── validate_tool_data() — missing name ──

	public function test_missing_name_returns_wp_error(): void {
		$data = $this->valid_tool_data();
		unset( $data['name'] );

		$result = McpToolValidator::validate_tool_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
		$this->assertSame( 'tool_validation_failed', $result->get_error_code() );
	}

	public function test_empty_name_returns_wp_error(): void {
		$data         = $this->valid_tool_data();
		$data['name'] = '';

		$result = McpToolValidator::validate_tool_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_invalid_name_chars_returns_wp_error(): void {
		$data         = $this->valid_tool_data();
		$data['name'] = 'invalid name!';

		$result = McpToolValidator::validate_tool_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_tool_data() — missing description ──

	public function test_missing_description_returns_wp_error(): void {
		$data = $this->valid_tool_data();
		unset( $data['description'] );

		$result = McpToolValidator::validate_tool_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_empty_description_returns_wp_error(): void {
		$data                = $this->valid_tool_data();
		$data['description'] = '';

		$result = McpToolValidator::validate_tool_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_tool_data() — invalid inputSchema ──

	public function test_non_array_input_schema_returns_wp_error(): void {
		$data                = $this->valid_tool_data();
		$data['inputSchema'] = 'not-an-array';

		$result = McpToolValidator::validate_tool_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_input_schema_with_non_object_type_returns_wp_error(): void {
		$data                = $this->valid_tool_data();
		$data['inputSchema'] = array( 'type' => 'string' );

		$result = McpToolValidator::validate_tool_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_missing_input_schema_returns_wp_error(): void {
		$data = $this->valid_tool_data();
		unset( $data['inputSchema'] );

		$result = McpToolValidator::validate_tool_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_tool_data() — context in error ──

	public function test_context_included_in_error_message(): void {
		$data = array();

		$result = McpToolValidator::validate_tool_data( $data, 'ability registration' );
		$this->assertTrue( is_wp_error( $result ) );
		$this->assertStringContainsString( 'ability registration', $result->get_error_message() );
	}

	// ── validate_tool_data() — annotations ──

	public function test_valid_annotations_pass(): void {
		$data                = $this->valid_tool_data();
		$data['annotations'] = array(
			'readOnlyHint' => true,
			'audience'     => array( 'user' ),
		);

		$this->assertTrue( McpToolValidator::validate_tool_data( $data ) );
	}

	public function test_invalid_annotations_return_wp_error(): void {
		$data                = $this->valid_tool_data();
		$data['annotations'] = array(
			'readOnlyHint' => 'not-a-boolean',
		);

		$result = McpToolValidator::validate_tool_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_non_array_annotations_return_wp_error(): void {
		$data                = $this->valid_tool_data();
		$data['annotations'] = 'invalid';

		$result = McpToolValidator::validate_tool_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_tool_data() — optional fields ──

	public function test_valid_title_passes(): void {
		$data          = $this->valid_tool_data();
		$data['title'] = 'My Tool Title';

		$this->assertTrue( McpToolValidator::validate_tool_data( $data ) );
	}

	public function test_non_string_title_returns_wp_error(): void {
		$data          = $this->valid_tool_data();
		$data['title'] = 123;

		$result = McpToolValidator::validate_tool_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── get_validation_errors() — schema properties validation ──

	public function test_non_array_properties_in_schema_returns_error(): void {
		$data                = $this->valid_tool_data();
		$data['inputSchema'] = array(
			'type'       => 'object',
			'properties' => 'invalid',
		);

		$errors = McpToolValidator::get_validation_errors( $data );
		$this->assertNotEmpty( $errors );
	}

	public function test_non_array_property_definition_returns_error(): void {
		$data                = $this->valid_tool_data();
		$data['inputSchema'] = array(
			'type'       => 'object',
			'properties' => array(
				'bad_prop' => 'not-an-array',
			),
		);

		$errors = McpToolValidator::get_validation_errors( $data );
		$this->assertNotEmpty( $errors );
	}

	public function test_required_field_not_in_properties_returns_error(): void {
		$data                = $this->valid_tool_data();
		$data['inputSchema'] = array(
			'type'       => 'object',
			'properties' => array(
				'name' => array( 'type' => 'string' ),
			),
			'required'   => array( 'nonexistent' ),
		);

		$errors = McpToolValidator::get_validation_errors( $data );
		$this->assertNotEmpty( $errors );
	}

	public function test_non_array_required_field_returns_error(): void {
		$data                = $this->valid_tool_data();
		$data['inputSchema'] = array(
			'type'     => 'object',
			'required' => 'name',
		);

		$errors = McpToolValidator::get_validation_errors( $data );
		$this->assertNotEmpty( $errors );
	}
}
