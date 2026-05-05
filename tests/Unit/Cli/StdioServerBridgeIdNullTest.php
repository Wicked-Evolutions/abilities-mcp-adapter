<?php
/**
 * #89: StdioServerBridge::handle_request() — id-state-aware response routing.
 *
 * Integration coverage of the full handle_request() body for the three
 * id-state cases. Pre-fix, an explicit id:null was indistinguishable from a
 * notification and got an empty response (causing spec-compliant clients to
 * hang); after fix, only an absent id member suppresses response emission.
 *
 * The bridge has McpServer + RequestRouter constructor dependencies. To
 * exercise handle_request() without standing those up, this test:
 *   1. Instantiates the bridge via newInstanceWithoutConstructor().
 *   2. Reflection-injects a stub server object (need only satisfy
 *      method_exists($this->server, 'get_observability_handler') = false,
 *      which is true for any stdClass).
 *   3. Reflection-injects an anonymous-class RequestRouter stub whose
 *      route_request() returns a JSON-RPC error envelope. The error envelope
 *      short-circuits ResponseRedactionGate::apply() at its early-return
 *      (line 60), so the test exercises the full handle_request() body
 *      including id-state branching but skips the redactor's work.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Cli
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Cli;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Cli\StdioServerBridge;
use WickedEvolutions\McpAdapter\Core\McpServer;
use WickedEvolutions\McpAdapter\Infrastructure\Observability\NullMcpObservabilityHandler;
use WickedEvolutions\McpAdapter\Transport\Infrastructure\RequestRouter;

final class StdioServerBridgeIdNullTest extends TestCase {

	private StdioServerBridge $bridge;

	protected function setUp(): void {
		$class = new \ReflectionClass( StdioServerBridge::class );
		$this->bridge = $class->newInstanceWithoutConstructor();

		// Inject an uninitialized McpServer to satisfy the property's typed
		// declaration. handle_request() consults
		// method_exists($this->server, 'get_observability_handler') — true on
		// the real class — and then calls it, which reads the typed
		// `observability_handler` property. Initialise that property to a
		// NullMcpObservabilityHandler so the lookup doesn't throw on the
		// uninitialized-property guard.
		$server_class = new \ReflectionClass( McpServer::class );
		$server_stub  = $server_class->newInstanceWithoutConstructor();
		$obs_prop     = $server_class->getProperty( 'observability_handler' );
		$obs_prop->setValue( $server_stub, new NullMcpObservabilityHandler() );

		$server_prop = $class->getProperty( 'server' );
		$server_prop->setValue( $this->bridge, $server_stub );

		// Inject a stub RequestRouter that returns a JSON-RPC error envelope
		// for any method. The error shape short-circuits
		// ResponseRedactionGate::apply() at its `isset($result['error'])`
		// early-return so we don't pull in the full redactor for this test.
		// Signature must match the parent's exactly (including default values).
		$router_stub = new class extends RequestRouter {
			public function __construct() {
				// Skip parent constructor — we don't need the full router.
			}
			public function route_request(
				string $method,
				array $params,
				$request_id = 0,
				string $transport_name = 'unknown',
				?\WickedEvolutions\McpAdapter\Transport\Infrastructure\HttpRequestContext $http_context = null
			): array {
				return array(
					'error' => array(
						'code'    => -32601,
						'message' => 'Method not found (stub)',
					),
				);
			}
		};
		$router_prop = $class->getProperty( 'request_router' );
		$router_prop->setValue( $this->bridge, $router_stub );
	}

	private function call_handle( string $json ): string {
		$method = new \ReflectionMethod( StdioServerBridge::class, 'handle_request' );
		// setAccessible() is a no-op since PHP 8.1 (deprecated 8.5+); reflected
		// private/protected methods are accessible without it.
		return (string) $method->invoke( $this->bridge, $json );
	}

	public function test_notification_no_id_key_returns_empty_string(): void {
		$response = $this->call_handle( '{"jsonrpc":"2.0","method":"test"}' );
		$this->assertSame( '', $response, 'Notification (no id member) must produce no response.' );
	}

	public function test_explicit_null_id_returns_response_with_null_id(): void {
		// THE FIX. Pre-#89 this returned '' and the client hung.
		$response = $this->call_handle( '{"jsonrpc":"2.0","method":"test","id":null}' );
		$this->assertNotSame( '', $response, 'id:null must receive a response (JSON-RPC §4).' );

		$decoded = json_decode( $response, true );
		$this->assertIsArray( $decoded );
		$this->assertArrayHasKey( 'id', $decoded, 'response must include the id member' );
		$this->assertNull( $decoded['id'], 'id:null in the request must round-trip to id:null in the response' );
		$this->assertSame( '2.0', $decoded['jsonrpc'] );
	}

	public function test_string_id_returns_response_with_same_id(): void {
		$response = $this->call_handle( '{"jsonrpc":"2.0","method":"test","id":"abc-123"}' );
		$this->assertNotSame( '', $response );
		$decoded = json_decode( $response, true );
		$this->assertSame( 'abc-123', $decoded['id'] );
	}

	public function test_int_id_returns_response_with_same_id(): void {
		$response = $this->call_handle( '{"jsonrpc":"2.0","method":"test","id":42}' );
		$this->assertNotSame( '', $response );
		$decoded = json_decode( $response, true );
		$this->assertSame( 42, $decoded['id'] );
	}

	public function test_zero_id_returns_response(): void {
		// Defensive: id:0 is falsy in PHP. Pin that we don't accidentally
		// suppress the response under any loose check.
		$response = $this->call_handle( '{"jsonrpc":"2.0","method":"test","id":0}' );
		$this->assertNotSame( '', $response );
		$decoded = json_decode( $response, true );
		$this->assertSame( 0, $decoded['id'] );
	}
}
