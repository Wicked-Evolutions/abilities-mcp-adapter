<?php

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Domain\Prompts;

use WickedEvolutions\McpAdapter\Domain\Prompts\McpPromptValidator;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class McpPromptValidatorTest extends TestCase {

	/**
	 * Build a minimal valid prompt data array.
	 */
	private function valid_prompt_data(): array {
		return array(
			'name'        => 'my-prompt',
			'description' => 'A test prompt',
		);
	}

	// ── validate_prompt_data() — valid ──

	public function test_valid_prompt_returns_true(): void {
		$this->assertTrue( McpPromptValidator::validate_prompt_data( $this->valid_prompt_data() ) );
	}

	public function test_valid_prompt_with_arguments_returns_true(): void {
		$data              = $this->valid_prompt_data();
		$data['arguments'] = array(
			array(
				'name'        => 'topic',
				'description' => 'The topic to write about',
				'required'    => true,
			),
		);

		$this->assertTrue( McpPromptValidator::validate_prompt_data( $data ) );
	}

	// ── validate_prompt_data() — missing name ──

	public function test_missing_name_returns_wp_error(): void {
		$data = $this->valid_prompt_data();
		unset( $data['name'] );

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
		$this->assertSame( 'prompt_validation_failed', $result->get_error_code() );
	}

	public function test_empty_name_returns_wp_error(): void {
		$data         = $this->valid_prompt_data();
		$data['name'] = '';

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_invalid_name_chars_returns_wp_error(): void {
		$data         = $this->valid_prompt_data();
		$data['name'] = 'has space';

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_prompt_data() — description ──

	public function test_prompt_without_description_is_valid(): void {
		$data = array( 'name' => 'my-prompt' );
		$this->assertTrue( McpPromptValidator::validate_prompt_data( $data ) );
	}

	public function test_non_string_description_returns_wp_error(): void {
		$data                = $this->valid_prompt_data();
		$data['description'] = 123;

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_prompt_data() — title ──

	public function test_non_string_title_returns_wp_error(): void {
		$data          = $this->valid_prompt_data();
		$data['title'] = 123;

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_valid_title_passes(): void {
		$data          = $this->valid_prompt_data();
		$data['title'] = 'Prompt Title';

		$this->assertTrue( McpPromptValidator::validate_prompt_data( $data ) );
	}

	// ── validate_prompt_data() — arguments validation ──

	public function test_non_array_arguments_returns_wp_error(): void {
		$data              = $this->valid_prompt_data();
		$data['arguments'] = 'invalid';

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_argument_without_name_returns_wp_error(): void {
		$data              = $this->valid_prompt_data();
		$data['arguments'] = array(
			array( 'description' => 'Missing name' ),
		);

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_argument_with_invalid_name_returns_wp_error(): void {
		$data              = $this->valid_prompt_data();
		$data['arguments'] = array(
			array( 'name' => str_repeat( 'x', 65 ) ), // exceeds 64 char limit
		);

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_argument_non_string_description_returns_wp_error(): void {
		$data              = $this->valid_prompt_data();
		$data['arguments'] = array(
			array(
				'name'        => 'arg1',
				'description' => 123,
			),
		);

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_argument_non_bool_required_returns_wp_error(): void {
		$data              = $this->valid_prompt_data();
		$data['arguments'] = array(
			array(
				'name'     => 'arg1',
				'required' => 'yes',
			),
		);

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_non_array_argument_item_returns_wp_error(): void {
		$data              = $this->valid_prompt_data();
		$data['arguments'] = array( 'not-an-array' );

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_prompt_data() — annotations ──

	public function test_valid_annotations_pass(): void {
		$data                = $this->valid_prompt_data();
		$data['annotations'] = array( 'priority' => 0.5 );

		$this->assertTrue( McpPromptValidator::validate_prompt_data( $data ) );
	}

	public function test_non_array_annotations_returns_wp_error(): void {
		$data                = $this->valid_prompt_data();
		$data['annotations'] = 'invalid';

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	public function test_invalid_annotations_returns_wp_error(): void {
		$data                = $this->valid_prompt_data();
		$data['annotations'] = array( 'priority' => 'high' );

		$result = McpPromptValidator::validate_prompt_data( $data );
		$this->assertTrue( is_wp_error( $result ) );
	}

	// ── validate_prompt_data() — context ──

	public function test_context_included_in_error_message(): void {
		$result = McpPromptValidator::validate_prompt_data( array(), 'test-context' );
		$this->assertTrue( is_wp_error( $result ) );
		$this->assertStringContainsString( 'test-context', $result->get_error_message() );
	}

	// ── validate_prompt_messages() ──

	public function test_valid_text_message_passes(): void {
		$messages = array(
			array(
				'role'    => 'user',
				'content' => array(
					'type' => 'text',
					'text' => 'Hello, world!',
				),
			),
		);
		$this->assertEmpty( McpPromptValidator::validate_prompt_messages( $messages ) );
	}

	public function test_invalid_role_returns_error(): void {
		$messages = array(
			array(
				'role'    => 'system',
				'content' => array(
					'type' => 'text',
					'text' => 'Hello',
				),
			),
		);
		$errors = McpPromptValidator::validate_prompt_messages( $messages );
		$this->assertNotEmpty( $errors );
	}

	public function test_missing_role_returns_error(): void {
		$messages = array(
			array(
				'content' => array(
					'type' => 'text',
					'text' => 'Hello',
				),
			),
		);
		$errors = McpPromptValidator::validate_prompt_messages( $messages );
		$this->assertNotEmpty( $errors );
	}

	public function test_missing_content_returns_error(): void {
		$messages = array(
			array( 'role' => 'user' ),
		);
		$errors = McpPromptValidator::validate_prompt_messages( $messages );
		$this->assertNotEmpty( $errors );
	}

	public function test_unsupported_content_type_returns_error(): void {
		$messages = array(
			array(
				'role'    => 'user',
				'content' => array(
					'type' => 'video',
				),
			),
		);
		$errors = McpPromptValidator::validate_prompt_messages( $messages );
		$this->assertNotEmpty( $errors );
	}

	public function test_non_array_message_returns_error(): void {
		$messages = array( 'not-an-array' );
		$errors   = McpPromptValidator::validate_prompt_messages( $messages );
		$this->assertNotEmpty( $errors );
	}
}
