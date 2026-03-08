<?php

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Domain\Utils;

use WickedEvolutions\McpAdapter\Domain\Utils\McpValidator;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class McpValidatorTest extends TestCase {

	// ── validate_name() ──

	public function test_validate_name_rejects_empty_string(): void {
		$this->assertFalse( McpValidator::validate_name( '' ) );
	}

	public function test_validate_name_rejects_too_long_string(): void {
		$name = str_repeat( 'a', 256 );
		$this->assertFalse( McpValidator::validate_name( $name ) );
	}

	public function test_validate_name_accepts_max_length_string(): void {
		$name = str_repeat( 'a', 255 );
		$this->assertTrue( McpValidator::validate_name( $name ) );
	}

	public function test_validate_name_accepts_valid_chars(): void {
		$this->assertTrue( McpValidator::validate_name( 'my-tool_Name123' ) );
	}

	public function test_validate_name_rejects_spaces(): void {
		$this->assertFalse( McpValidator::validate_name( 'has space' ) );
	}

	public function test_validate_name_rejects_special_chars(): void {
		$this->assertFalse( McpValidator::validate_name( 'has@char' ) );
		$this->assertFalse( McpValidator::validate_name( 'has.dot' ) );
		$this->assertFalse( McpValidator::validate_name( 'has/slash' ) );
	}

	public function test_validate_name_respects_custom_max_length(): void {
		$this->assertTrue( McpValidator::validate_name( 'abcde', 5 ) );
		$this->assertFalse( McpValidator::validate_name( 'abcdef', 5 ) );
	}

	// ── validate_tool_or_prompt_name() ──

	public function test_validate_tool_or_prompt_name_delegates_with_255_max(): void {
		$this->assertTrue( McpValidator::validate_tool_or_prompt_name( 'valid-name' ) );
		$this->assertFalse( McpValidator::validate_tool_or_prompt_name( '' ) );
		$this->assertFalse( McpValidator::validate_tool_or_prompt_name( str_repeat( 'x', 256 ) ) );
	}

	// ── validate_ability_name() ──

	public function test_validate_ability_name_accepts_two_segments(): void {
		$this->assertTrue( McpValidator::validate_ability_name( 'content/list' ) );
	}

	public function test_validate_ability_name_accepts_three_segments(): void {
		$this->assertTrue( McpValidator::validate_ability_name( 'fluent-crm/contacts/list' ) );
	}

	public function test_validate_ability_name_accepts_four_segments(): void {
		$this->assertTrue( McpValidator::validate_ability_name( 'a/b/c/d' ) );
	}

	public function test_validate_ability_name_rejects_one_segment(): void {
		$this->assertFalse( McpValidator::validate_ability_name( 'single' ) );
	}

	public function test_validate_ability_name_rejects_five_segments(): void {
		$this->assertFalse( McpValidator::validate_ability_name( 'a/b/c/d/e' ) );
	}

	public function test_validate_ability_name_rejects_uppercase(): void {
		$this->assertFalse( McpValidator::validate_ability_name( 'Content/List' ) );
	}

	public function test_validate_ability_name_rejects_special_chars(): void {
		$this->assertFalse( McpValidator::validate_ability_name( 'con@tent/list' ) );
		$this->assertFalse( McpValidator::validate_ability_name( 'content/li_st' ) );
	}

	public function test_validate_ability_name_rejects_empty_segments(): void {
		$this->assertFalse( McpValidator::validate_ability_name( 'content/' ) );
		$this->assertFalse( McpValidator::validate_ability_name( '/list' ) );
		$this->assertFalse( McpValidator::validate_ability_name( 'content//list' ) );
	}

	public function test_validate_ability_name_rejects_empty(): void {
		$this->assertFalse( McpValidator::validate_ability_name( '' ) );
	}

	public function test_validate_ability_name_rejects_too_long(): void {
		$segment = str_repeat( 'a', 126 );
		$name    = $segment . '/' . $segment; // 253 chars, valid length
		$this->assertTrue( McpValidator::validate_ability_name( $name ) );

		$long_name = str_repeat( 'a', 128 ) . '/' . str_repeat( 'a', 128 ); // 257 > 255
		$this->assertFalse( McpValidator::validate_ability_name( $long_name ) );
	}

	// ── validate_argument_name() ──

	public function test_validate_argument_name_accepts_valid(): void {
		$this->assertTrue( McpValidator::validate_argument_name( 'my_arg' ) );
	}

	public function test_validate_argument_name_max_64(): void {
		$this->assertTrue( McpValidator::validate_argument_name( str_repeat( 'a', 64 ) ) );
		$this->assertFalse( McpValidator::validate_argument_name( str_repeat( 'a', 65 ) ) );
	}

	// ── validate_mime_type() ──

	public function test_validate_mime_type_accepts_valid(): void {
		$this->assertTrue( McpValidator::validate_mime_type( 'text/plain' ) );
		$this->assertTrue( McpValidator::validate_mime_type( 'application/json' ) );
		$this->assertTrue( McpValidator::validate_mime_type( 'image/png' ) );
	}

	public function test_validate_mime_type_rejects_invalid(): void {
		$this->assertFalse( McpValidator::validate_mime_type( 'invalid' ) );
		$this->assertFalse( McpValidator::validate_mime_type( '/json' ) );
		$this->assertFalse( McpValidator::validate_mime_type( 'text/' ) );
		$this->assertFalse( McpValidator::validate_mime_type( '' ) );
	}

	// ── validate_resource_uri() ──

	public function test_validate_resource_uri_accepts_valid(): void {
		$this->assertTrue( McpValidator::validate_resource_uri( 'https://example.com' ) );
		$this->assertTrue( McpValidator::validate_resource_uri( 'file:///path/to/file' ) );
		$this->assertTrue( McpValidator::validate_resource_uri( 'custom-scheme:data' ) );
	}

	public function test_validate_resource_uri_rejects_invalid(): void {
		$this->assertFalse( McpValidator::validate_resource_uri( '' ) );
		$this->assertFalse( McpValidator::validate_resource_uri( 'no-scheme' ) );
		$this->assertFalse( McpValidator::validate_resource_uri( '://missing-scheme' ) );
	}

	public function test_validate_resource_uri_rejects_too_long(): void {
		$uri = 'https://' . str_repeat( 'a', 2050 );
		$this->assertFalse( McpValidator::validate_resource_uri( $uri ) );
	}

	// ── validate_role() ──

	public function test_validate_role_accepts_user_and_assistant(): void {
		$this->assertTrue( McpValidator::validate_role( 'user' ) );
		$this->assertTrue( McpValidator::validate_role( 'assistant' ) );
	}

	public function test_validate_role_rejects_invalid(): void {
		$this->assertFalse( McpValidator::validate_role( 'admin' ) );
		$this->assertFalse( McpValidator::validate_role( '' ) );
	}

	// ── validate_roles_array() ──

	public function test_validate_roles_array_accepts_valid(): void {
		$this->assertTrue( McpValidator::validate_roles_array( array( 'user' ) ) );
		$this->assertTrue( McpValidator::validate_roles_array( array( 'user', 'assistant' ) ) );
	}

	public function test_validate_roles_array_rejects_empty(): void {
		$this->assertFalse( McpValidator::validate_roles_array( array() ) );
	}

	public function test_validate_roles_array_rejects_invalid_role(): void {
		$this->assertFalse( McpValidator::validate_roles_array( array( 'user', 'admin' ) ) );
	}

	public function test_validate_roles_array_rejects_non_string(): void {
		$this->assertFalse( McpValidator::validate_roles_array( array( 123 ) ) );
	}

	// ── validate_priority() ──

	public function test_validate_priority_accepts_valid_range(): void {
		$this->assertTrue( McpValidator::validate_priority( 0.0 ) );
		$this->assertTrue( McpValidator::validate_priority( 0.5 ) );
		$this->assertTrue( McpValidator::validate_priority( 1.0 ) );
		$this->assertTrue( McpValidator::validate_priority( 0 ) );
		$this->assertTrue( McpValidator::validate_priority( 1 ) );
	}

	public function test_validate_priority_rejects_out_of_range(): void {
		$this->assertFalse( McpValidator::validate_priority( -0.1 ) );
		$this->assertFalse( McpValidator::validate_priority( 1.1 ) );
	}

	public function test_validate_priority_rejects_non_numeric(): void {
		$this->assertFalse( McpValidator::validate_priority( 'high' ) );
	}

	// ── validate_iso8601_timestamp() ──

	public function test_validate_iso8601_accepts_utc(): void {
		$this->assertTrue( McpValidator::validate_iso8601_timestamp( '2026-03-08T12:00:00Z' ) );
	}

	public function test_validate_iso8601_accepts_timezone_offset(): void {
		$this->assertTrue( McpValidator::validate_iso8601_timestamp( '2026-03-08T12:00:00+02:00' ) );
	}

	public function test_validate_iso8601_rejects_invalid(): void {
		$this->assertFalse( McpValidator::validate_iso8601_timestamp( 'not-a-date' ) );
		$this->assertFalse( McpValidator::validate_iso8601_timestamp( '2026-03-08' ) );
	}

	// ── validate_base64() ──

	public function test_validate_base64_accepts_valid(): void {
		$this->assertTrue( McpValidator::validate_base64( base64_encode( 'hello' ) ) );
	}

	public function test_validate_base64_rejects_empty(): void {
		$this->assertFalse( McpValidator::validate_base64( '' ) );
	}

	// ── validate_image_mime_type() ──

	public function test_validate_image_mime_type_accepts_valid(): void {
		$this->assertTrue( McpValidator::validate_image_mime_type( 'image/png' ) );
		$this->assertTrue( McpValidator::validate_image_mime_type( 'image/jpeg' ) );
	}

	public function test_validate_image_mime_type_rejects_non_image(): void {
		$this->assertFalse( McpValidator::validate_image_mime_type( 'text/plain' ) );
	}

	// ── validate_audio_mime_type() ──

	public function test_validate_audio_mime_type_accepts_valid(): void {
		$this->assertTrue( McpValidator::validate_audio_mime_type( 'audio/mpeg' ) );
	}

	public function test_validate_audio_mime_type_rejects_non_audio(): void {
		$this->assertFalse( McpValidator::validate_audio_mime_type( 'video/mp4' ) );
	}

	// ── get_tool_annotation_validation_errors() ──

	public function test_tool_annotation_errors_empty_for_valid(): void {
		$annotations = array(
			'readOnlyHint'    => true,
			'destructiveHint' => false,
			'idempotentHint'  => true,
			'openWorldHint'   => false,
			'title'           => 'My Tool',
		);
		$this->assertSame( array(), McpValidator::get_tool_annotation_validation_errors( $annotations ) );
	}

	public function test_tool_annotation_errors_for_non_bool_hints(): void {
		$annotations = array( 'readOnlyHint' => 'yes' );
		$errors      = McpValidator::get_tool_annotation_validation_errors( $annotations );
		$this->assertCount( 1, $errors );
		$this->assertStringContainsString( 'readOnlyHint', $errors[0] );
	}

	public function test_tool_annotation_errors_for_empty_title(): void {
		$annotations = array( 'title' => '   ' );
		$errors      = McpValidator::get_tool_annotation_validation_errors( $annotations );
		$this->assertCount( 1, $errors );
		$this->assertStringContainsString( 'title', $errors[0] );
	}

	public function test_tool_annotation_errors_for_non_string_title(): void {
		$annotations = array( 'title' => 123 );
		$errors      = McpValidator::get_tool_annotation_validation_errors( $annotations );
		$this->assertCount( 1, $errors );
	}

	public function test_tool_annotation_errors_ignores_unknown_fields(): void {
		$annotations = array( 'unknownField' => 'value' );
		$this->assertSame( array(), McpValidator::get_tool_annotation_validation_errors( $annotations ) );
	}

	// ── get_annotation_validation_errors() ──

	public function test_annotation_errors_empty_for_valid(): void {
		$annotations = array(
			'audience'     => array( 'user' ),
			'lastModified' => '2026-03-08T12:00:00Z',
			'priority'     => 0.5,
		);
		$this->assertSame( array(), McpValidator::get_annotation_validation_errors( $annotations ) );
	}

	public function test_annotation_errors_for_non_array_audience(): void {
		$errors = McpValidator::get_annotation_validation_errors( array( 'audience' => 'user' ) );
		$this->assertCount( 1, $errors );
		$this->assertStringContainsString( 'audience', $errors[0] );
	}

	public function test_annotation_errors_for_empty_audience(): void {
		$errors = McpValidator::get_annotation_validation_errors( array( 'audience' => array() ) );
		$this->assertCount( 1, $errors );
	}

	public function test_annotation_errors_for_invalid_roles_in_audience(): void {
		$errors = McpValidator::get_annotation_validation_errors( array( 'audience' => array( 'admin' ) ) );
		$this->assertCount( 1, $errors );
	}

	public function test_annotation_errors_for_invalid_last_modified(): void {
		$errors = McpValidator::get_annotation_validation_errors( array( 'lastModified' => 'not-a-date' ) );
		$this->assertCount( 1, $errors );
		$this->assertStringContainsString( 'ISO 8601', $errors[0] );
	}

	public function test_annotation_errors_for_empty_last_modified(): void {
		$errors = McpValidator::get_annotation_validation_errors( array( 'lastModified' => '' ) );
		$this->assertCount( 1, $errors );
	}

	public function test_annotation_errors_for_non_numeric_priority(): void {
		$errors = McpValidator::get_annotation_validation_errors( array( 'priority' => 'high' ) );
		$this->assertCount( 1, $errors );
	}

	public function test_annotation_errors_for_out_of_range_priority(): void {
		$errors = McpValidator::get_annotation_validation_errors( array( 'priority' => 1.5 ) );
		$this->assertCount( 1, $errors );
		$this->assertStringContainsString( 'between 0.0 and 1.0', $errors[0] );
	}

	public function test_annotation_errors_ignores_unknown_fields(): void {
		$this->assertSame( array(), McpValidator::get_annotation_validation_errors( array( 'custom' => 'value' ) ) );
	}
}
