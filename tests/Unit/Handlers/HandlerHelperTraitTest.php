<?php
/**
 * Tests for HandlerHelperTrait.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Handlers;

use WickedEvolutions\McpAdapter\Handlers\HandlerHelperTrait;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

/**
 * Concrete class that uses the trait so we can test its methods.
 */
class HandlerHelperTraitConsumer {
	use HandlerHelperTrait {
		extract_params as public;
		create_error_response as public;
		extract_error as public;
		create_success_response as public;
	}
}

class HandlerHelperTraitTest extends TestCase {

	/**
	 * @var HandlerHelperTraitConsumer
	 */
	private HandlerHelperTraitConsumer $helper;

	protected function setUp(): void {
		parent::setUp();
		$this->helper = new HandlerHelperTraitConsumer();
	}

	// --- extract_params ---

	public function test_extract_params_with_nested_params(): void {
		$data = array(
			'params' => array(
				'name'  => 'content/list',
				'limit' => 10,
			),
		);

		$result = $this->helper->extract_params( $data );

		$this->assertSame( array( 'name' => 'content/list', 'limit' => 10 ), $result );
	}

	public function test_extract_params_with_root_params(): void {
		$data = array(
			'name'  => 'content/list',
			'limit' => 10,
		);

		$result = $this->helper->extract_params( $data );

		// When no 'params' key exists, the entire data array is returned.
		$this->assertSame( array( 'name' => 'content/list', 'limit' => 10 ), $result );
	}

	public function test_extract_params_prefers_nested_over_root(): void {
		$data = array(
			'params' => array( 'nested' => true ),
			'root'   => true,
		);

		$result = $this->helper->extract_params( $data );

		$this->assertSame( array( 'nested' => true ), $result );
		$this->assertArrayNotHasKey( 'root', $result );
	}

	// --- create_error_response ---

	public function test_create_error_response_format(): void {
		$result = $this->helper->create_error_response( -32601, 'Method not found', 42 );

		$this->assertArrayHasKey( 'id', $result );
		$this->assertArrayHasKey( 'error', $result );
		$this->assertSame( 42, $result['id'] );
		$this->assertSame( -32601, $result['error']['code'] );
		$this->assertSame( 'Method not found', $result['error']['message'] );
	}

	public function test_create_error_response_default_request_id(): void {
		$result = $this->helper->create_error_response( -32603, 'Internal error' );

		$this->assertSame( 0, $result['id'] );
	}

	// --- extract_error ---

	public function test_extract_error_unwraps_factory_response(): void {
		$factory_response = array(
			'error' => array(
				'code'    => -32602,
				'message' => 'Invalid params',
			),
		);

		$result = $this->helper->extract_error( $factory_response );

		$this->assertSame( -32602, $result['code'] );
		$this->assertSame( 'Invalid params', $result['message'] );
	}

	public function test_extract_error_returns_as_is_without_error_key(): void {
		$raw = array(
			'code'    => -32603,
			'message' => 'Internal error',
		);

		$result = $this->helper->extract_error( $raw );

		// Falls back to returning the entire array when no 'error' key.
		$this->assertSame( -32603, $result['code'] );
		$this->assertSame( 'Internal error', $result['message'] );
	}

	// --- create_success_response ---

	public function test_create_success_response_format(): void {
		$data = array( 'tools' => array( 'content/list' ) );

		$result = $this->helper->create_success_response( $data );

		$this->assertArrayHasKey( 'result', $result );
		$this->assertSame( $data, $result['result'] );
	}

	public function test_create_success_response_with_scalar(): void {
		$result = $this->helper->create_success_response( 'ok' );

		$this->assertSame( array( 'result' => 'ok' ), $result );
	}

	public function test_create_success_response_with_null(): void {
		$result = $this->helper->create_success_response( null );

		$this->assertSame( array( 'result' => null ), $result );
	}
}
