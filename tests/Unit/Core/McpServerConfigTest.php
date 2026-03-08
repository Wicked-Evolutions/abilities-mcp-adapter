<?php
/**
 * Tests for McpServerConfig.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Core;

use WickedEvolutions\McpAdapter\Core\McpServerConfig;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class McpServerConfigTest extends TestCase {

	/**
	 * Full configuration array used across tests.
	 *
	 * @var array
	 */
	private array $full_config;

	protected function setUp(): void {
		parent::setUp();

		$this->full_config = array(
			'server_id'                     => 'test-server',
			'server_route_namespace'        => 'mcp/v1',
			'server_route'                  => '/mcp',
			'server_name'                   => 'Test MCP Server',
			'server_description'            => 'A test server for unit testing.',
			'server_version'                => '1.0.0',
			'mcp_transports'                => array( 'StreamableHttpTransport' ),
			'error_handler'                 => 'SomeErrorHandler',
			'observability_handler'         => 'SomeObservabilityHandler',
			'tools'                         => array( 'content/list', 'content/get' ),
			'resources'                     => array( 'site/info' ),
			'prompts'                       => array( 'greeting' ),
			'transport_permission_callback' => function() { return true; },
		);
	}

	// --- from_array creates valid config ---

	public function test_from_array_creates_valid_config(): void {
		$config = McpServerConfig::from_array( $this->full_config );

		$this->assertInstanceOf( McpServerConfig::class, $config );
	}

	// --- Getter tests ---

	public function test_get_server_id(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertSame( 'test-server', $config->get_server_id() );
	}

	public function test_get_server_route_namespace(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertSame( 'mcp/v1', $config->get_server_route_namespace() );
	}

	public function test_get_server_route(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertSame( '/mcp', $config->get_server_route() );
	}

	public function test_get_server_name(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertSame( 'Test MCP Server', $config->get_server_name() );
	}

	public function test_get_server_description(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertSame( 'A test server for unit testing.', $config->get_server_description() );
	}

	public function test_get_server_version(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertSame( '1.0.0', $config->get_server_version() );
	}

	public function test_get_mcp_transports(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertSame( array( 'StreamableHttpTransport' ), $config->get_mcp_transports() );
	}

	public function test_get_error_handler(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertSame( 'SomeErrorHandler', $config->get_error_handler() );
	}

	public function test_get_observability_handler(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertSame( 'SomeObservabilityHandler', $config->get_observability_handler() );
	}

	public function test_get_tools(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertSame( array( 'content/list', 'content/get' ), $config->get_tools() );
	}

	public function test_get_resources(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertSame( array( 'site/info' ), $config->get_resources() );
	}

	public function test_get_prompts(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertSame( array( 'greeting' ), $config->get_prompts() );
	}

	public function test_get_transport_permission_callback(): void {
		$config = McpServerConfig::from_array( $this->full_config );
		$this->assertIsCallable( $config->get_transport_permission_callback() );
	}

	// --- Defaults for optional fields ---

	public function test_default_error_handler_is_null(): void {
		$config = McpServerConfig::from_array( array(
			'server_id' => 'minimal',
		) );
		$this->assertNull( $config->get_error_handler() );
	}

	public function test_default_observability_handler_is_null(): void {
		$config = McpServerConfig::from_array( array(
			'server_id' => 'minimal',
		) );
		$this->assertNull( $config->get_observability_handler() );
	}

	public function test_default_tools_is_empty_array(): void {
		$config = McpServerConfig::from_array( array(
			'server_id' => 'minimal',
		) );
		$this->assertSame( array(), $config->get_tools() );
	}

	public function test_default_resources_is_empty_array(): void {
		$config = McpServerConfig::from_array( array(
			'server_id' => 'minimal',
		) );
		$this->assertSame( array(), $config->get_resources() );
	}

	public function test_default_prompts_is_empty_array(): void {
		$config = McpServerConfig::from_array( array(
			'server_id' => 'minimal',
		) );
		$this->assertSame( array(), $config->get_prompts() );
	}

	public function test_default_transports_is_empty_array(): void {
		$config = McpServerConfig::from_array( array(
			'server_id' => 'minimal',
		) );
		$this->assertSame( array(), $config->get_mcp_transports() );
	}

	public function test_default_transport_permission_callback_is_null(): void {
		$config = McpServerConfig::from_array( array(
			'server_id' => 'minimal',
		) );
		$this->assertNull( $config->get_transport_permission_callback() );
	}

	// --- from_array with missing optional fields ---

	public function test_from_array_with_only_required_fields(): void {
		$config = McpServerConfig::from_array( array(
			'server_id'              => 'bare-minimum',
			'server_route_namespace' => 'test/v1',
			'server_route'           => '/test',
			'server_name'            => 'Bare Minimum',
			'server_description'     => 'Minimal config.',
			'server_version'         => '0.1.0',
		) );

		$this->assertSame( 'bare-minimum', $config->get_server_id() );
		$this->assertSame( 'test/v1', $config->get_server_route_namespace() );
		$this->assertSame( '/test', $config->get_server_route() );
		$this->assertSame( 'Bare Minimum', $config->get_server_name() );
		$this->assertSame( 'Minimal config.', $config->get_server_description() );
		$this->assertSame( '0.1.0', $config->get_server_version() );
		$this->assertNull( $config->get_error_handler() );
		$this->assertNull( $config->get_observability_handler() );
		$this->assertSame( array(), $config->get_tools() );
		$this->assertSame( array(), $config->get_resources() );
		$this->assertSame( array(), $config->get_prompts() );
		$this->assertNull( $config->get_transport_permission_callback() );
	}

	public function test_from_array_with_empty_array_defaults_strings_to_empty(): void {
		$config = McpServerConfig::from_array( array() );

		$this->assertSame( '', $config->get_server_id() );
		$this->assertSame( '', $config->get_server_route_namespace() );
		$this->assertSame( '', $config->get_server_route() );
		$this->assertSame( '', $config->get_server_name() );
		$this->assertSame( '', $config->get_server_description() );
		$this->assertSame( '', $config->get_server_version() );
	}
}
