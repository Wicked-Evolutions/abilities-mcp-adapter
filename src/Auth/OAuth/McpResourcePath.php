<?php
/**
 * Canonical MCP resource path constants — single source of truth (#54).
 *
 * The MCP REST endpoint path was previously hard-coded across four files
 * (AuthorizationServer, AuthorizeEndpoint, DiscoveryEndpoints, helpers.php).
 * Drift between callsites would silently narrow Bearer auth or break
 * resource validation. All callsites now consume this class so a future
 * route rename is a one-line change.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

/**
 * Constants only. Never instantiated.
 */
final class McpResourcePath {

	/** REST namespace under /wp-json/. */
	public const REST_NAMESPACE = 'mcp';

	/** Route name within the namespace. */
	public const ROUTE = 'mcp-adapter-default-server';

	/** REST path for `rest_url()` — no leading slash. */
	public const PATH = self::REST_NAMESPACE . '/' . self::ROUTE;

	/** REST path with leading slash — for REQUEST_URI / rest_route compares. */
	public const LEADING_SLASH_PATH = '/' . self::REST_NAMESPACE . '/' . self::ROUTE;
}
