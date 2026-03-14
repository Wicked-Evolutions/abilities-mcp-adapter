<?php
/**
 * Initialize method handler for MCP requests.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Handlers\Initialize;

use WickedEvolutions\McpAdapter\Core\McpServer;
use stdClass;

/**
 * Handles the initialize MCP method.
 */
class InitializeHandler {
	/**
	 * The WordPress MCP instance.
	 *
	 * @var \WickedEvolutions\McpAdapter\Core\McpServer
	 */
	private McpServer $mcp;

	/**
	 * Constructor.
	 *
	 * @param \WickedEvolutions\McpAdapter\Core\McpServer $mcp The WordPress MCP instance.
	 */
	public function __construct( McpServer $mcp ) {
		$this->mcp = $mcp;
	}

	/**
	 * Supported MCP protocol versions, ordered oldest to newest.
	 *
	 * @var string[]
	 */
	private const SUPPORTED_VERSIONS = array( '2025-06-18', '2025-11-25' );

	/**
	 * Handles the initialize request with protocol version negotiation.
	 *
	 * The server reflects back the client's requested protocol version if supported,
	 * or falls back to the latest version the server supports. This eliminates the
	 * need for transport-layer version rewriting (e.g. in the SSH bridge).
	 *
	 * @param array $params     The client's initialization parameters. Default empty.
	 * @param int   $request_id Optional. The request ID for JSON-RPC. Default 0.
	 *
	 * @return array Response with server capabilities and information.
	 */
	public function handle( array $params = array(), int $request_id = 0 ): array {
		// Version negotiation: reflect client version if supported, else latest supported.
		$client_version     = $params['protocolVersion'] ?? self::SUPPORTED_VERSIONS[0];
		$latest_supported   = self::SUPPORTED_VERSIONS[ count( self::SUPPORTED_VERSIONS ) - 1 ];
		$negotiated_version = in_array( $client_version, self::SUPPORTED_VERSIONS, true )
			? $client_version
			: $latest_supported;

		$server_info = array(
			'name'    => $this->mcp->get_server_name(),
			'version' => $this->mcp->get_server_version(),
		);

		// Capabilities — empty objects declare support without requiring
		// sub-capability declarations. Valid for both 2025-06-18 and 2025-11-25.
		$capabilities = array(
			'tools'       => new stdClass(),
			'resources'   => new stdClass(),
			'prompts'     => new stdClass(),
			'logging'     => new stdClass(),
			'completions' => new stdClass(),
		);

		return array(
			'protocolVersion' => $negotiated_version,
			'serverInfo'      => $server_info,
			'capabilities'    => (object) $capabilities,
			'instructions'    => $this->mcp->get_server_description(),
		);
	}
}
