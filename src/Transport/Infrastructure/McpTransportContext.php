<?php
/**
 * Transport context object for dependency injection.
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Transport\Infrastructure;

use WickedEvolutions\McpAdapter\Core\McpServer;
use WickedEvolutions\McpAdapter\Handlers\Initialize\InitializeHandler;
use WickedEvolutions\McpAdapter\Handlers\Prompts\PromptsHandler;
use WickedEvolutions\McpAdapter\Handlers\Resources\ResourcesHandler;
use WickedEvolutions\McpAdapter\Handlers\System\SystemHandler;
use WickedEvolutions\McpAdapter\Handlers\Tools\ToolsHandler;
use WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\Contracts\McpErrorHandlerInterface;
use WickedEvolutions\McpAdapter\Infrastructure\Observability\Contracts\McpObservabilityHandlerInterface;

/**
 * Transport context object for dependency injection.
 *
 * Contains all dependencies needed by transport implementations,
 * promoting loose coupling and easier testing.
 *
 * Note: The request_router parameter is optional. If not provided,
 * a RequestRouter instance will be automatically created with this
 * context as its dependency.
 */
class McpTransportContext {

	/**
	 * Initialize the transport context.
	 *
	 * @param \WickedEvolutions\McpAdapter\Core\McpServer             $mcp_server The MCP server instance.
	 * @param \WickedEvolutions\McpAdapter\Handlers\Initialize\InitializeHandler     $initialize_handler The initialize handler.
	 * @param \WickedEvolutions\McpAdapter\Handlers\Tools\ToolsHandler          $tools_handler The tools handler.
	 * @param \WickedEvolutions\McpAdapter\Handlers\Resources\ResourcesHandler      $resources_handler The resources handler.
	 * @param \WickedEvolutions\McpAdapter\Handlers\Prompts\PromptsHandler        $prompts_handler The prompts handler.
	 * @param \WickedEvolutions\McpAdapter\Handlers\System\SystemHandler         $system_handler The system handler.
	 * @param string                $observability_handler The observability handler class name.
	 * @param \WickedEvolutions\McpAdapter\Transport\Infrastructure\RequestRouter|null $request_router The request router service.
	 * @param callable|null         $transport_permission_callback Optional custom permission callback for transport-level authentication.
	 */
	/**
	 * The MCP server instance.
	 *
	 * @var \WickedEvolutions\McpAdapter\Core\McpServer
	 */
	public McpServer $mcp_server;

	/**
	 * The initialize handler.
	 *
	 * @var \WickedEvolutions\McpAdapter\Handlers\Initialize\InitializeHandler
	 */
	public InitializeHandler $initialize_handler;

	/**
	 * The tools handler.
	 *
	 * @var \WickedEvolutions\McpAdapter\Handlers\Tools\ToolsHandler
	 */
	public ToolsHandler $tools_handler;

	/**
	 * The resources handler.
	 *
	 * @var \WickedEvolutions\McpAdapter\Handlers\Resources\ResourcesHandler
	 */
	public ResourcesHandler $resources_handler;

	/**
	 * The prompts handler.
	 *
	 * @var \WickedEvolutions\McpAdapter\Handlers\Prompts\PromptsHandler
	 */
	public PromptsHandler $prompts_handler;

	/**
	 * The system handler.
	 *
	 * @var \WickedEvolutions\McpAdapter\Handlers\System\SystemHandler
	 */
	public SystemHandler $system_handler;

	/**
	 * The observability handler instance.
	 *
	 * @var \WickedEvolutions\McpAdapter\Infrastructure\Observability\Contracts\McpObservabilityHandlerInterface
	 */
	public McpObservabilityHandlerInterface $observability_handler;

	/**
	 * The error handler instance.
	 *
	 * @var \WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\Contracts\McpErrorHandlerInterface
	 */
	public McpErrorHandlerInterface $error_handler;

	/**
	 * The request router service.
	 */
	public RequestRouter $request_router;

	/**
	 * Optional custom permission callback for transport-level authentication.
	 *
	 * @var callable|callable-string|null
	 */
	public $transport_permission_callback;

	/**
	 * Initialize the transport context.
	 *
	 * @param array{
	 *   mcp_server: \WickedEvolutions\McpAdapter\Core\McpServer,
	 *   initialize_handler: \WickedEvolutions\McpAdapter\Handlers\Initialize\InitializeHandler,
	 *   tools_handler: \WickedEvolutions\McpAdapter\Handlers\Tools\ToolsHandler,
	 *   resources_handler: \WickedEvolutions\McpAdapter\Handlers\Resources\ResourcesHandler,
	 *   prompts_handler: \WickedEvolutions\McpAdapter\Handlers\Prompts\PromptsHandler,
	 *   system_handler: \WickedEvolutions\McpAdapter\Handlers\System\SystemHandler,
	 *   observability_handler: \WickedEvolutions\McpAdapter\Infrastructure\Observability\Contracts\McpObservabilityHandlerInterface,
	 *   request_router?: \WickedEvolutions\McpAdapter\Transport\Infrastructure\RequestRouter,
	 *   transport_permission_callback?: callable|null,
	 *   error_handler?: \WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\Contracts\McpErrorHandlerInterface
	 * } $properties Properties to set on the context.
	 * Note: request_router is optional and will be auto-created if not provided.
	 */
	public function __construct( array $properties ) {
		foreach ( $properties as $name => $value ) {
			$this->$name = $value;
		}

		// If request_router is provided, we're done
		if ( isset( $properties['request_router'] ) ) {
			return;
		}

		// Create request_router if not provided
		$this->request_router = new RequestRouter( $this );
	}
}
