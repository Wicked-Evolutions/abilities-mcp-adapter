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
	 * Controlled enum of reasons the auth gate denied a request. The boundary
	 * log only ever sees one of these — detailed exception text stays in
	 * `error_log()` and never reaches third-party listeners.
	 */
	public const AUTH_DENY_INVALID_CREDENTIALS = 'invalid_credentials';
	public const AUTH_DENY_MISSING_ORIGIN      = 'missing_origin';
	public const AUTH_DENY_EXPIRED_TOKEN       = 'expired_token';
	public const AUTH_DENY_PERMISSION_DENIED   = 'permission_denied';
	public const AUTH_DENY_DISALLOWED_ORIGIN   = 'disallowed_origin';
	public const AUTH_DENY_MALFORMED_REQUEST   = 'malformed_request';
	public const AUTH_DENY_UNKNOWN             = 'unknown';

	/**
	 * @var string[] Whitelist used to coerce free-form input to the enum.
	 */
	private const AUTH_DENY_REASONS = array(
		self::AUTH_DENY_INVALID_CREDENTIALS,
		self::AUTH_DENY_MISSING_ORIGIN,
		self::AUTH_DENY_EXPIRED_TOKEN,
		self::AUTH_DENY_PERMISSION_DENIED,
		self::AUTH_DENY_DISALLOWED_ORIGIN,
		self::AUTH_DENY_MALFORMED_REQUEST,
		self::AUTH_DENY_UNKNOWN,
	);

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

		// Suppress WordPress core's default CORS handling ONLY for requests
		// targeting our MCP route namespace. Core's `rest_send_cors_headers()`
		// (registered on `rest_pre_serve_request` at priority 10) echoes any
		// Origin without an allowlist check and uses a header allowlist that
		// excludes `Mcp-Session-Id` / `Mcp-Session-Token`. We replace it on
		// MCP routes only — every other REST endpoint on the site keeps core's
		// behaviour untouched. Hooked at priority 9 so we run before core's 10.
		add_filter( 'rest_pre_serve_request', array( $this, 'maybe_disable_core_cors_for_mcp' ), 9, 4 );

		// Emit our own CORS headers on every dispatched REST response. Filtering
		// at this layer (rather than per-route) ensures headers are present on
		// error responses too, including the 401/403 returned by check_permission.
		add_filter( 'rest_post_dispatch', array( $this, 'emit_cors_headers' ), 10, 3 );
	}

	/**
	 * Conditionally disable WordPress core's CORS callback for MCP routes.
	 *
	 * Runs at `rest_pre_serve_request` priority 9 (before core's 10). When
	 * the dispatched request targets this transport's namespace, we remove
	 * `rest_send_cors_headers` from the same hook for the remainder of this
	 * request — core won't run, our `emit_cors_headers` handles CORS instead.
	 * Non-MCP REST routes are not affected.
	 *
	 * @param mixed             $served  Whether the request has already been served.
	 * @param mixed             $result  Response result (unused).
	 * @param \WP_REST_Request|null $request The dispatched REST request.
	 * @param \WP_REST_Server|null  $server  The REST server (unused).
	 *
	 * @return mixed The unchanged $served value.
	 */
	public function maybe_disable_core_cors_for_mcp( $served, $result = null, $request = null, $server = null ) {
		if ( ! $request instanceof \WP_REST_Request ) {
			return $served;
		}
		if ( ! $this->is_mcp_route( $request ) ) {
			return $served;
		}
		// Only act if core's callback is still attached.
		if ( function_exists( 'has_filter' ) && false !== has_filter( 'rest_pre_serve_request', 'rest_send_cors_headers' ) ) {
			remove_filter( 'rest_pre_serve_request', 'rest_send_cors_headers' );
		}
		return $served;
	}

	/**
	 * Whether a REST request targets this transport's route namespace.
	 *
	 * @param \WP_REST_Request<array<string, mixed>> $request
	 * @return bool
	 */
	private function is_mcp_route( \WP_REST_Request $request ): bool {
		$mcp_server = $this->request_handler->transport_context->mcp_server;
		$ns         = $mcp_server->get_server_route_namespace();
		$route      = (string) $request->get_route();
		return strpos( $route, '/' . $ns . '/' ) === 0;
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
				// Detail (the WP_Error message) stays in error_handler->log only;
				// the boundary event sees the controlled enum.
				if ( is_wp_error( $result ) ) {
					$this->request_handler->transport_context->error_handler->log(
						'Permission callback returned WP_Error: ' . $result->get_error_message(),
						array( 'HttpTransport::check_permission' )
					);
					$this->emit_auth_denied( $context, self::AUTH_DENY_PERMISSION_DENIED );
					return false;
				}

				// Return the boolean result directly.
				if ( ! (bool) $result ) {
					$this->emit_auth_denied( $context, self::AUTH_DENY_PERMISSION_DENIED );
				}

				return (bool) $result;
			} catch ( \Throwable $e ) {
				// Exception: log internally, deny access (fail closed).
				// Exception text stays in error_handler->log only.
				$this->request_handler->transport_context->error_handler->log(
					'Error in transport permission callback: ' . $e->getMessage(),
					array( 'HttpTransport::check_permission' )
				);
				$this->emit_auth_denied( $context, self::AUTH_DENY_UNKNOWN );
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
			// Capability name stays in error_handler->log only; the boundary
			// event sees the controlled enum.
			$this->request_handler->transport_context->error_handler->log(
				sprintf( 'Permission denied for MCP API access. User ID %d does not have capability "%s"', $user_id, $user_capability ),
				array( 'HttpTransport::check_permission' )
			);
			$this->emit_auth_denied( $context, self::AUTH_DENY_PERMISSION_DENIED );
		}

		return $user_has_capability;
	}

	/**
	 * Emit a `boundary.auth.denied` event through the observability emitter.
	 *
	 * Tags are metadata-only and pass through a strict enum — no free-form
	 * reason text, no raw IPs, no exception strings reach third-party
	 * listeners. Detailed exception/log text stays in `error_log()` only,
	 * recorded by the caller through the regular error handler.
	 *
	 * The IP is truncated to /24 (IPv4) or /48 (IPv6) BEFORE tag construction
	 * so the raw address never enters the emitter pipeline.
	 *
	 * @param HttpRequestContext $context     The HTTP request context.
	 * @param string             $reason_enum One of {@see AUTH_DENY_REASONS}; anything
	 *                                        else is coerced to AUTH_DENY_UNKNOWN.
	 */
	private function emit_auth_denied( HttpRequestContext $context, string $reason_enum ): void {
		$server_obj = $this->request_handler->transport_context->mcp_server;
		$handler    = $server_obj && method_exists( $server_obj, 'get_observability_handler' )
			? $server_obj->get_observability_handler()
			: null;

		$raw_ip = isset( $_SERVER['REMOTE_ADDR'] ) && is_string( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '';

		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) && is_string( $_SERVER['HTTP_USER_AGENT'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) )
			: '';

		$reason = in_array( $reason_enum, self::AUTH_DENY_REASONS, true )
			? $reason_enum
			: self::AUTH_DENY_UNKNOWN;

		$tags = array(
			'severity'    => 'warn',
			'transport'   => 'HTTP',
			'ip'          => self::truncate_ip_for_log( $raw_ip ),
			'user_agent'  => $user_agent,
			'session_id'  => $context->session_id ?? '',
			'user_id'     => function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0,
			'error_code'  => $reason,
			'status_code' => 401,
			'reason'      => $reason,
		);

		BoundaryEventEmitter::emit( $handler, 'boundary.auth.denied', $tags );
	}

	/**
	 * Truncate a client IP for boundary-log tagging (PII policy).
	 *
	 * IPv4 → /24, IPv6 → /48. Mirrors DB-4's RateLimiter pattern; inlined
	 * here so DB-5 doesn't take a hard dependency on the rate-limiter PR.
	 * Public so the same algorithm is exercised by unit tests directly.
	 *
	 * @param string $ip
	 * @return string Truncated IP string, or '' if the input is empty/invalid.
	 */
	public static function truncate_ip_for_log( string $ip ): string {
		if ( '' === $ip ) {
			return '';
		}
		if ( false === @inet_pton( $ip ) ) {
			return '';
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			if ( 4 !== count( $parts ) ) {
				return '';
			}
			return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
		}
		$bin = @inet_pton( $ip );
		if ( false === $bin || strlen( $bin ) !== 16 ) {
			return '';
		}
		$groups = str_split( bin2hex( $bin ), 4 );
		return $groups[0] . ':' . $groups[1] . ':' . $groups[2] . '::/48';
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
		if ( ! $this->is_mcp_route( $request ) ) {
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
