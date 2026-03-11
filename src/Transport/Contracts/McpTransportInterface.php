<?php
/**
 * Interface for MCP transport protocols.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Transport\Contracts;

use WickedEvolutions\McpAdapter\Transport\Infrastructure\McpTransportContext;

/**
 * Base interface for MCP transport protocols.
 *
 * This interface defines the core contract for all MCP transport implementations,
 * providing common functionality for initialization and route registration.
 * Specific transport protocols should extend this interface with their own
 * request handling methods.
 */
interface McpTransportInterface {

	/**
	 * Initialize the transport with provided context.
	 *
	 * @param \WickedEvolutions\McpAdapter\Transport\Infrastructure\McpTransportContext $context Dependency injection container.
	 */
	public function __construct( McpTransportContext $context );

	/**
	 * Register transport-specific routes.
	 *
	 * Called during WordPress REST API initialization to register
	 * endpoints for this transport.
	 */
	public function register_routes(): void;
}
