<?php
/**
 * MCP HTTP Transport for WordPress - MCP 2025-06-18 Compliant
 *
 * This transport implements the MCP Streamable HTTP specification and can work
 * both with and without the mcp-wordpress-remote proxy.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Transport;

use WickedEvolutions\McpAdapter\Infrastructure\Observability\BoundaryEventEmitter;
use WickedEvolutions\McpAdapter\Transport\Contracts\McpRestTransportInterface;
use WickedEvolutions\McpAdapter\Transport\Infrastructure\HttpRequestContext;
use WickedEvolutions\McpAdapter\Transport\Infrastructure\HttpRequestHandler;
use WickedEvolutions\McpAdapter\Transport\Infrastructure\McpTransportContext;
use WickedEvolutions\McpAdapter\Transport\Infrastructure\McpTransportHelperTrait;

/**
 * MCP HTTP Transport - Unified transport for both proxy and direct clients
 *
 * Implements MCP 2025-06-18 Streamable HTTP specification
 */
class HttpTransport implements McpRestTransportInterface {
	use McpTransportHelperTrait;

	/**
	 * The HTTP request handler.
	 *
	 * @var \WickedEvolutions\McpAdapter\Transport\Infrastructure\HttpRequestHandler
	 */
	protected HttpRequestHandler $request_handler;

	/**
	 * Initialize the class and register routes
	 *
	 * @param \WickedEvolutions\McpAdapter\Transport\Infrastructure\McpTransportContext $transport_context The transport context.
	 */
	public function __construct( McpTransportContext $transport_context ) {
		$this->request_handler = new HttpRequestHandler( $transport_context );
		add_action( 'rest_api_init', array( $this, 'register_routes' ), 16 );
	}

	/**
	 * Register MCP HTTP routes
	 */
	public function register_routes(): void {
		// Get server info from request handler's transport context
		$server = $this->request_handler->transport_context->mcp_server;

		// Single endpoint for MCP communication (POST, GET for SSE, DELETE for session termination)
		register_rest_route(
			$server->get_server_route_namespace(),
			$server->get_server_route(),
			array(
				'methods'             => array( 'POST', 'GET', 'DELETE' ),
				'callback'            => array( $this, 'handle_request' ),
				'permission_callback' => array( $this, 'check_permission' ),
			)
		);
	}

	/**
	 * Check if the user has permission to access the MCP API
	 *
	 * @param \WP_REST_Request<array<string, mixed>> $request The request object.
	 *
	 * @return bool True if the user has permission, false otherwise.
	 */
	public function check_permission( \WP_REST_Request $request ) {
		$context = new HttpRequestContext( $request );

		// Check permission using callback or default
		$transport_context = $this->request_handler->transport_context;

		if ( null !== $transport_context->transport_permission_callback ) {
			try {
				$result = call_user_func( $transport_context->transport_permission_callback, $context->request );

				// WP_Error return: log internally, deny access (fail closed).
				if ( is_wp_error( $result ) ) {
					$this->request_handler->transport_context->error_handler->log(
						'Permission callback returned WP_Error: ' . $result->get_error_message(),
						array( 'HttpTransport::check_permission' )
					);
					$this->emit_auth_denied( $context, 'permission_callback_error', $result->get_error_message() );
					return false;
				}

				// Return the boolean result directly.
				if ( ! (bool) $result ) {
					$this->emit_auth_denied( $context, 'permission_callback_denied' );
				}

				return (bool) $result;
			} catch ( \Throwable $e ) {
				// Exception: log internally, deny access (fail closed).
				$this->request_handler->transport_context->error_handler->log(
					'Error in transport permission callback: ' . $e->getMessage(),
					array( 'HttpTransport::check_permission' )
				);
				$this->emit_auth_denied( $context, 'permission_callback_exception', $e->getMessage() );
				return false;
			}
		}
		$user_capability = apply_filters( 'mcp_adapter_default_transport_permission_user_capability', 'read', $context );

		// Validate that the filtered capability is a non-empty string
		if ( ! is_string( $user_capability ) || empty( $user_capability ) ) {
			$user_capability = 'read';
		}

		$user_has_capability = current_user_can( $user_capability ); // phpcs:ignore WordPress.WP.Capabilities.Undetermined -- Capability is filtered and defaults to 'read'

		if ( ! $user_has_capability ) {
			$user_id = get_current_user_id();
			$this->request_handler->transport_context->error_handler->log(
				sprintf( 'Permission denied for MCP API access. User ID %d does not have capability "%s"', $user_id, $user_capability ),
				array( 'HttpTransport::check_permission' )
			);
			$this->emit_auth_denied( $context, 'missing_capability', $user_capability );
		}

		return $user_has_capability;
	}

	/**
	 * Emit a `boundary.auth.denied` event through the observability emitter.
	 *
	 * Tags are metadata-only (request id, session id, IP, user agent, error
	 * code) — no headers, body, or capability values that would carry
	 * identifying or sensitive data.
	 *
	 * @param HttpRequestContext $context    The HTTP request context.
	 * @param string             $error_code Why the denial happened.
	 * @param string             $reason     Optional short human reason.
	 */
	private function emit_auth_denied( HttpRequestContext $context, string $error_code, string $reason = '' ): void {
		$server_obj = $this->request_handler->transport_context->mcp_server;
		$handler    = $server_obj && method_exists( $server_obj, 'get_observability_handler' )
			? $server_obj->get_observability_handler()
			: null;

		$ip = isset( $_SERVER['REMOTE_ADDR'] ) && is_string( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '';

		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) && is_string( $_SERVER['HTTP_USER_AGENT'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) )
			: '';

		$tags = array(
			'severity'    => 'warn',
			'transport'   => 'HTTP',
			'ip'          => $ip,
			'user_agent'  => $user_agent,
			'session_id'  => $context->session_id ?? '',
			'user_id'     => get_current_user_id(),
			'error_code'  => $error_code,
			'status_code' => 401,
			'reason'      => $reason,
		);

		BoundaryEventEmitter::emit( $handler, 'boundary.auth.denied', $tags );
	}

	/**
	 * Handle HTTP requests according to MCP 2025-06-18 specification
	 *
	 * @param \WP_REST_Request<array<string, mixed>> $request The request object.
	 *
	 * @return \WP_REST_Response
	 */
	public function handle_request( \WP_REST_Request $request ): \WP_REST_Response {
		$context = new HttpRequestContext( $request );

		return $this->request_handler->handle_request( $context );
	}
}
