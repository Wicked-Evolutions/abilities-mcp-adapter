<?php

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Domain\Utils;

use WickedEvolutions\McpAdapter\Domain\Utils\SchemaTransformer;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class SchemaTransformerTest extends TestCase {

	public function test_null_schema_returns_minimal_object(): void {
		$result = SchemaTransformer::transform_to_object_schema( null );

		$this->assertSame( 'object', $result['schema']['type'] );
		$this->assertFalse( $result['schema']['additionalProperties'] );
		$this->assertFalse( $result['was_transformed'] );
		$this->assertNull( $result['wrapper_property'] );
	}

	public function test_empty_array_returns_minimal_object(): void {
		$result = SchemaTransformer::transform_to_object_schema( array() );

		$this->assertSame( 'object', $result['schema']['type'] );
		$this->assertFalse( $result['was_transformed'] );
	}

	public function test_object_type_schema_returned_unchanged(): void {
		$schema = array(
			'type'       => 'object',
			'properties' => array(
				'name' => array( 'type' => 'string' ),
			),
		);
		$result = SchemaTransformer::transform_to_object_schema( $schema );

		$this->assertSame( $schema, $result['schema'] );
		$this->assertFalse( $result['was_transformed'] );
		$this->assertNull( $result['wrapper_property'] );
	}

	public function test_string_type_schema_wrapped_in_object(): void {
		$schema = array( 'type' => 'string', 'description' => 'A name' );
		$result = SchemaTransformer::transform_to_object_schema( $schema );

		$this->assertTrue( $result['was_transformed'] );
		$this->assertSame( 'input', $result['wrapper_property'] );
		$this->assertSame( 'object', $result['schema']['type'] );
		$this->assertSame( $schema, $result['schema']['properties']['input'] );
		$this->assertSame( array( 'input' ), $result['schema']['required'] );
	}

	public function test_array_type_schema_wrapped_in_object(): void {
		$schema = array(
			'type'  => 'array',
			'items' => array( 'type' => 'string' ),
		);
		$result = SchemaTransformer::transform_to_object_schema( $schema );

		$this->assertTrue( $result['was_transformed'] );
		$this->assertSame( 'input', $result['wrapper_property'] );
		$this->assertSame( $schema, $result['schema']['properties']['input'] );
	}

	public function test_custom_wrapper_key(): void {
		$schema = array( 'type' => 'number' );
		$result = SchemaTransformer::transform_to_object_schema( $schema, 'value' );

		$this->assertTrue( $result['was_transformed'] );
		$this->assertSame( 'value', $result['wrapper_property'] );
		$this->assertArrayHasKey( 'value', $result['schema']['properties'] );
		$this->assertSame( array( 'value' ), $result['schema']['required'] );
	}

	public function test_schema_without_type_returned_as_is(): void {
		$schema = array( 'description' => 'No type field' );
		$result = SchemaTransformer::transform_to_object_schema( $schema );

		$this->assertSame( $schema, $result['schema'] );
		$this->assertFalse( $result['was_transformed'] );
		$this->assertNull( $result['wrapper_property'] );
	}

	public function test_boolean_type_schema_wrapped(): void {
		$schema = array( 'type' => 'boolean' );
		$result = SchemaTransformer::transform_to_object_schema( $schema );

		$this->assertTrue( $result['was_transformed'] );
		$this->assertSame( 'object', $result['schema']['type'] );
	}

	public function test_integer_type_schema_wrapped(): void {
		$schema = array( 'type' => 'integer' );
		$result = SchemaTransformer::transform_to_object_schema( $schema );

		$this->assertTrue( $result['was_transformed'] );
		$this->assertSame( 'object', $result['schema']['type'] );
		$this->assertSame( $schema, $result['schema']['properties']['input'] );
	}
}
