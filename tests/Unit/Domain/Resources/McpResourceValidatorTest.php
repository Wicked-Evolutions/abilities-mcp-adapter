<?php

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Domain\Resources;

use WickedEvolutions\McpAdapter\Domain\Resources\McpResourceValidator;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class McpResourceValidatorTest extends TestCase {

	/**
	 * Build a minimal valid resource data array.
	 */
	private function valid_resource_data(): array {
		return array(
			'uri'  => 'https://example.com/resource',
			'name' => 'test-resource',
			'text' => 'Resource content here',
		);
	}

	// ── validate_resource_data() — valid ──

	public function test_valid_resource_returns_true(): void {
		$this->assertTrue( McpResourceValidator::validate_resource_data( $this->valid_resource_data() ) );
	}

	public function test_valid_resource_with_blob_returns_true(): void {
		$data = array(
			'uri'      => 'file:///image.png',
			'blob'     => base64_encode( 'binary data' ),
			'mimeType' => 'image/png',
		);
		$this->assertTrue( McpResourceValidator::validate_resource_data( $data ) );
	}

	// ── validate_resource_data() — missing URI ──

	public function test_missing_uri_returns_wp_error(): void {
		$data = $this->valid_resource_data();
		unset( $data['uri'] );

		$result = McpResourceValidator::validate_resource_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
		$this->assertSame( 'resource_validation_failed', $result->get_error_code() );
	}

	public function test_empty_uri_returns_wp_error(): void {
		$data        = $this->valid_resource_data();
		$data['uri'] = '';

		$result = McpResourceValidator::validate_resource_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_resource_data() — invalid URI ──

	public function test_invalid_uri_format_returns_wp_error(): void {
		$data        = $this->valid_resource_data();
		$data['uri'] = 'not-a-valid-uri';

		$result = McpResourceValidator::validate_resource_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_resource_data() — content requirements ──

	public function test_no_text_or_blob_returns_wp_error(): void {
		$data = array(
			'uri'  => 'https://example.com/resource',
			'name' => 'test',
		);

		$result = McpResourceValidator::validate_resource_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_both_text_and_blob_returns_wp_error(): void {
		$data = array(
			'uri'  => 'https://example.com/resource',
			'text' => 'content',
			'blob' => base64_encode( 'data' ),
		);

		$result = McpResourceValidator::validate_resource_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_resource_data() — optional fields ──

	public function test_invalid_mime_type_returns_wp_error(): void {
		$data             = $this->valid_resource_data();
		$data['mimeType'] = 'invalid';

		$result = McpResourceValidator::validate_resource_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_valid_mime_type_passes(): void {
		$data             = $this->valid_resource_data();
		$data['mimeType'] = 'text/plain';

		$this->assertTrue( McpResourceValidator::validate_resource_data( $data ) );
	}

	public function test_non_string_name_returns_wp_error(): void {
		$data         = $this->valid_resource_data();
		$data['name'] = 123;

		$result = McpResourceValidator::validate_resource_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_non_string_description_returns_wp_error(): void {
		$data                = $this->valid_resource_data();
		$data['description'] = 123;

		$result = McpResourceValidator::validate_resource_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_resource_data() — annotations ──

	public function test_valid_annotations_pass(): void {
		$data                = $this->valid_resource_data();
		$data['annotations'] = array( 'audience' => array( 'user' ) );

		$this->assertTrue( McpResourceValidator::validate_resource_data( $data ) );
	}

	public function test_non_array_annotations_returns_wp_error(): void {
		$data                = $this->valid_resource_data();
		$data['annotations'] = 'invalid';

		$result = McpResourceValidator::validate_resource_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_invalid_annotations_returns_wp_error(): void {
		$data                = $this->valid_resource_data();
		$data['annotations'] = array( 'audience' => 'not-an-array' );

		$result = McpResourceValidator::validate_resource_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_resource_data() — context ──

	public function test_context_included_in_error_message(): void {
		$result = McpResourceValidator::validate_resource_data( array(), 'test context' );
		$this->assertTrue( is_wp_error( $result ) );
		$this->assertStringContainsString( 'test context', $result->get_error_message() );
	}

	// ── get_validation_errors() edge cases ──

	public function test_non_string_text_content_returns_error(): void {
		$data = array(
			'uri'  => 'https://example.com',
			'text' => 123,
		);
		$errors = McpResourceValidator::get_validation_errors( $data );
		$this->assertNotEmpty( $errors );
	}

	public function test_non_string_blob_content_returns_error(): void {
		$data = array(
			'uri'  => 'https://example.com',
			'blob' => 123,
		);
		$errors = McpResourceValidator::get_validation_errors( $data );
		$this->assertNotEmpty( $errors );
	}

	public function test_non_string_mime_type_returns_error(): void {
		$data = array(
			'uri'      => 'https://example.com',
			'text'     => 'content',
			'mimeType' => 123,
		);
		$errors = McpResourceValidator::get_validation_errors( $data );
		$this->assertNotEmpty( $errors );
	}
}
