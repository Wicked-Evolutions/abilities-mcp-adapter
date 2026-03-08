<?php
/**
 * Tests for output_schema passthrough from ability registration to MCP tool definition.
 *
 * Verifies XP6: output_schema from ability registration flows through to MCP tool definition.
 */

namespace WickedEvolutions\McpAdapter\Tests\Unit\Domain\Tools;

use WickedEvolutions\McpAdapter\Domain\Tools\McpTool;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class OutputSchemaPassthroughTest extends TestCase {

	private function make_tool( ?array $output_schema = null ): McpTool {
		return new McpTool(
			'test/tool',           // ability
			'test-tool',           // name
			'Test tool description', // description
			array( 'type' => 'object', 'properties' => array() ), // input_schema
			null,                  // title
			$output_schema         // output_schema
		);
	}

	public function test_output_schema_included_in_tool_data(): void {
		$output_schema = array(
			'type'       => 'object',
			'properties' => array(
				'results' => array(
					'type'  => 'array',
					'items' => array( 'type' => 'object' ),
				),
			),
			'required'   => array( 'results' ),
		);

		$tool      = $this->make_tool( $output_schema );
		$tool_data = $tool->to_array();

		$this->assertArrayHasKey( 'outputSchema', $tool_data );
		$this->assertSame( $output_schema, $tool_data['outputSchema'] );
	}

	public function test_output_schema_omitted_when_null(): void {
		$tool      = $this->make_tool();
		$tool_data = $tool->to_array();

		$this->assertArrayNotHasKey( 'outputSchema', $tool_data );
	}

	public function test_output_schema_getter_setter(): void {
		$tool = $this->make_tool();
		$this->assertNull( $tool->get_output_schema() );

		$schema = array(
			'type'       => 'object',
			'properties' => array(
				'id' => array( 'type' => 'integer' ),
			),
		);

		$tool->set_output_schema( $schema );
		$this->assertSame( $schema, $tool->get_output_schema() );

		$tool_data = $tool->to_array();
		$this->assertArrayHasKey( 'outputSchema', $tool_data );
		$this->assertSame( $schema, $tool_data['outputSchema'] );
	}

	public function test_output_schema_validated_by_tool_validator(): void {
		$tool_data = array(
			'name'         => 'test-tool',
			'description'  => 'Test',
			'inputSchema'  => array( 'type' => 'object', 'properties' => array() ),
			'outputSchema' => 'not-an-array',
		);

		$result = \WickedEvolutions\McpAdapter\Domain\Tools\McpToolValidator::validate_tool_data( $tool_data );

		$this->assertNotEmpty( $result );
	}
}
