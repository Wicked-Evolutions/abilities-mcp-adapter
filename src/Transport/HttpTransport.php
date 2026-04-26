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
use WickedEvolutions\McpAdapter\Transport\Infrastructure\OriginValidator;

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

		// Disable WordPress core's default CORS handling for the entire REST API.
		// Core's `rest_send_cors_headers()` echoes any Origin without an allowlist
		// check and uses a header allowlist that excludes `Mcp-Session-Id` and
		// `Mcp-Session-Token`. We replace it with our own per-response emission
		// (see emit_cors_headers()) gated by OriginValidator.
		add_filter( 'rest_send_cors_headers', '__return_false' );

		// Emit our own CORS headers on every dispatched REST response. Filtering
		// at this layer (rather than per-route) ensures headers are present on
		// error responses too, including the 401/403 returned by check_permission.
		add_filter( 'rest_post_dispatch', array( $this, 'emit_cors_headers' ), 10, 3 );
	}

	/**
	 * Register MCP HTTP routes
	 */
	public function register_routes(): void {
		// Get server info from request handler's transport context
		$server = $this->request_handler->transport_context->mcp_server;

		// Single endpoint for MCP communication.
		// POST = JSON-RPC requests, GET = SSE stream, DELETE = session termination,
		// OPTIONS = CORS preflight (handled before permission_callback by short-circuit).
		register_rest_route(
			$server->get_server_route_namespace(),
			$server->get_server_route(),
			array(
				'methods'             => array( 'POST', 'GET', 'DELETE', 'OPTIONS' ),
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

		// Origin allowlist runs BEFORE auth. Defense-in-depth against DNS rebinding.
		// Independent of authentication: a request with an allowed Origin and no
		// auth still gets 401; a request with valid auth from a disallowed Origin
		// still gets 403. Both checks are independent.
		//
		// OPTIONS (preflight) skips the Origin check here so the browser can
		// negotiate; handle_preflight() applies its own allowlist when deciding
		// whether to echo Access-Control-Allow-Origin.
		if ( 'OPTIONS' !== $context->method && ! OriginValidator::is_allowed( $request ) ) {
			$this->request_handler->record_transport_error(
				$context,
				'origin_not_allowed',
				403,
				array( 'origin' => $this->safe_origin_tag( $request ) )
			);
			return new \WP_Error(
				'rest_forbidden',
				'Origin not allowed',
				array( 'status' => 403 )
			);
		}

		// OPTIONS preflight is permitted unconditionally — the actual cross-origin
		// decision is made via the echoed Allow-Origin header (or its absence).
		if ( 'OPTIONS' === $context->method ) {
			return true;
		}

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

		if ( 'OPTIONS' === $context->method ) {
			return $this->handle_preflight( $request );
		}

		return $this->request_handler->handle_request( $context );
	}

	/**
	 * Handle CORS preflight (OPTIONS) requests.
	 *
	 * Returns 204 No Content with full CORS headers. Origin echo is gated by
	 * OriginValidator: disallowed origins get a 204 with NO Allow-Origin header,
	 * which causes the browser to fail the preflight (correct behaviour). We do
	 * not return 403 on disallowed Origin for OPTIONS — preflight failures are
	 * signalled by header absence, per CORS spec.
	 *
	 * @param \WP_REST_Request<array<string, mixed>> $request The request object.
	 * @return \WP_REST_Response 204 response with CORS headers.
	 */
	private function handle_preflight( \WP_REST_Request $request ): \WP_REST_Response {
		$response = new \WP_REST_Response( null, 204 );

		$echo_origin = OriginValidator::echoable_origin( $request );
		if ( '' !== $echo_origin ) {
			$response->header( 'Access-Control-Allow-Origin', $echo_origin );
			$response->header( 'Access-Control-Allow-Credentials', 'true' );
			$response->header( 'Access-Control-Allow-Methods', 'POST, GET, DELETE, OPTIONS' );
			$response->header( 'Access-Control-Allow-Headers', 'Content-Type, Mcp-Session-Id, Mcp-Session-Token, Authorization' );
			$response->header( 'Access-Control-Max-Age', '600' );
		}

		// Always advertise that responses vary by Origin so caches keyed on URL
		// alone don't serve a same-origin-cached response to a cross-origin client.
		$response->header( 'Vary', 'Origin' );

		return $response;
	}

	/**
	 * Emit CORS headers on every dispatched REST response that targets this
	 * transport's namespace. Wired via `rest_post_dispatch` in the constructor.
	 *
	 * Wildcard `*` is never used — incompatible with Allow-Credentials: true.
	 * Echo is gated by OriginValidator; disallowed Origins receive no
	 * Access-Control-Allow-Origin header and the browser's same-origin policy
	 * blocks the response client-side.
	 *
	 * @param \WP_HTTP_Response                       $response The dispatched response.
	 * @param \WP_REST_Server                         $server   The REST server instance.
	 * @param \WP_REST_Request<array<string, mixed>> $request  The original request.
	 *
	 * @return \WP_HTTP_Response
	 */
	public function emit_cors_headers( $response, $server, $request ) {
		if ( ! $response instanceof \WP_REST_Response || ! $request instanceof \WP_REST_Request ) {
			return $response;
		}

		// Only act on requests for this transport's route namespace.
		$mcp_server = $this->request_handler->transport_context->mcp_server;
		$ns         = $mcp_server->get_server_route_namespace();
		$route      = $request->get_route();
		if ( strpos( $route, '/' . $ns . '/' ) !== 0 ) {
			return $response;
		}

		// Vary: Origin is always set so shared caches don't cross-serve responses.
		$response->header( 'Vary', 'Origin' );

		$echo_origin = OriginValidator::echoable_origin( $request );
		if ( '' === $echo_origin ) {
			return $response;
		}

		$response->header( 'Access-Control-Allow-Origin', $echo_origin );
		$response->header( 'Access-Control-Allow-Credentials', 'true' );
		$response->header( 'Access-Control-Expose-Headers', 'Mcp-Session-Id, Mcp-Session-Token' );

		return $response;
	}

	/**
	 * Sanitize the Origin header for use as an observability tag.
	 *
	 * Truncates to a sensible length and strips control characters; the raw
	 * header value would otherwise pass through to telemetry. Returns '' when
	 * no Origin was present (server-to-server bridge traffic).
	 *
	 * @param \WP_REST_Request<array<string, mixed>> $request The REST request.
	 * @return string Sanitised Origin string suitable for logging.
	 */
	private function safe_origin_tag( \WP_REST_Request $request ): string {
		$origin = $request->get_header( 'origin' );
		if ( ! is_string( $origin ) || '' === $origin ) {
			return '';
		}
		$origin = sanitize_text_field( $origin );
		if ( strlen( $origin ) > 255 ) {
			$origin = substr( $origin, 0, 255 );
		}
		return $origin;
	}
}
