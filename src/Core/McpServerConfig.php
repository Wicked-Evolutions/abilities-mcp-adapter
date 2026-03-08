<?php
/**
 * Configuration object for MCP Server creation.
 *
 * Replaces the 13-parameter God Constructor in McpAdapter::create_server().
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Core;

use WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\Contracts\McpErrorHandlerInterface;
use WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\NullMcpErrorHandler;
use WickedEvolutions\McpAdapter\Infrastructure\Observability\Contracts\McpObservabilityHandlerInterface;
use WickedEvolutions\McpAdapter\Infrastructure\Observability\NullMcpObservabilityHandler;

/**
 * Immutable configuration object for MCP Server creation.
 */
class McpServerConfig {

	/**
	 * @var string Unique server identifier.
	 */
	private string $server_id;

	/**
	 * @var string Server route namespace (REST API namespace).
	 */
	private string $server_route_namespace;

	/**
	 * @var string Server route.
	 */
	private string $server_route;

	/**
	 * @var string Human-readable server name.
	 */
	private string $server_name;

	/**
	 * @var string Server description.
	 */
	private string $server_description;

	/**
	 * @var string Server version.
	 */
	private string $server_version;

	/**
	 * @var array Transport class names.
	 */
	private array $mcp_transports;

	/**
	 * @var string|null Error handler class name.
	 */
	private ?string $error_handler;

	/**
	 * @var string|null Observability handler class name.
	 */
	private ?string $observability_handler;

	/**
	 * @var array Ability names to register as tools.
	 */
	private array $tools;

	/**
	 * @var array Ability names to register as resources.
	 */
	private array $resources;

	/**
	 * @var array Prompts to register.
	 */
	private array $prompts;

	/**
	 * @var callable|null Transport-level permission callback.
	 */
	private $transport_permission_callback;

	/**
	 * Create a config from an associative array.
	 *
	 * @param array $config Configuration array.
	 *
	 * @return self
	 */
	public static function from_array( array $config ): self {
		$instance = new self();

		$instance->server_id                     = $config['server_id'] ?? '';
		$instance->server_route_namespace        = $config['server_route_namespace'] ?? '';
		$instance->server_route                  = $config['server_route'] ?? '';
		$instance->server_name                   = $config['server_name'] ?? '';
		$instance->server_description            = $config['server_description'] ?? '';
		$instance->server_version                = $config['server_version'] ?? '';
		$instance->mcp_transports                = $config['mcp_transports'] ?? array();
		$instance->error_handler                 = $config['error_handler'] ?? null;
		$instance->observability_handler         = $config['observability_handler'] ?? null;
		$instance->tools                         = $config['tools'] ?? array();
		$instance->resources                     = $config['resources'] ?? array();
		$instance->prompts                       = $config['prompts'] ?? array();
		$instance->transport_permission_callback = $config['transport_permission_callback'] ?? null;

		return $instance;
	}

	/**
	 * Private constructor — use from_array().
	 */
	private function __construct() {
	}

	/**
	 * @return string
	 */
	public function get_server_id(): string {
		return $this->server_id;
	}

	/**
	 * @return string
	 */
	public function get_server_route_namespace(): string {
		return $this->server_route_namespace;
	}

	/**
	 * @return string
	 */
	public function get_server_route(): string {
		return $this->server_route;
	}

	/**
	 * @return string
	 */
	public function get_server_name(): string {
		return $this->server_name;
	}

	/**
	 * @return string
	 */
	public function get_server_description(): string {
		return $this->server_description;
	}

	/**
	 * @return string
	 */
	public function get_server_version(): string {
		return $this->server_version;
	}

	/**
	 * @return array
	 */
	public function get_mcp_transports(): array {
		return $this->mcp_transports;
	}

	/**
	 * @return string|null
	 */
	public function get_error_handler(): ?string {
		return $this->error_handler;
	}

	/**
	 * @return string|null
	 */
	public function get_observability_handler(): ?string {
		return $this->observability_handler;
	}

	/**
	 * @return array
	 */
	public function get_tools(): array {
		return $this->tools;
	}

	/**
	 * @return array
	 */
	public function get_resources(): array {
		return $this->resources;
	}

	/**
	 * @return array
	 */
	public function get_prompts(): array {
		return $this->prompts;
	}

	/**
	 * @return callable|null
	 */
	public function get_transport_permission_callback(): ?callable {
		return $this->transport_permission_callback;
	}
}
