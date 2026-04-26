<?php
/**
 * Service for routing MCP requests to appropriate handlers.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Transport\Infrastructure;

use WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\McpErrorFactory;
use WickedEvolutions\McpAdapter\Infrastructure\Observability\BoundaryEventEmitter;
use WickedEvolutions\McpAdapter\RateLimit\RateLimiter;
use WickedEvolutions\McpAdapter\RateLimit\TrustedProxyResolver;

/**
 * Service for routing MCP requests to appropriate handlers.
 *
 * Extracted from AbstractMcpTransport to be reusable across
 * all transport implementations via dependency injection.
 */
class RequestRouter {

	/**
	 * The transport context.
	 *
	 * @var \WickedEvolutions\McpAdapter\Transport\Infrastructure\McpTransportContext
	 */
	private McpTransportContext $context;

	/**
	 * Rate limiter used to short-circuit hot callers before handler dispatch.
	 *
	 * @var \WickedEvolutions\McpAdapter\RateLimit\RateLimiter
	 */
	private RateLimiter $rate_limiter;

	/**
	 * Initialize the request router.
	 *
	 * @param \WickedEvolutions\McpAdapter\Transport\Infrastructure\McpTransportContext $context      The transport context.
	 * @param \WickedEvolutions\McpAdapter\RateLimit\RateLimiter|null                   $rate_limiter Optional limiter (mainly for tests).
	 */
	public function __construct(
		McpTransportContext $context,
		?RateLimiter $rate_limiter = null
	) {
		$this->context      = $context;
		$this->rate_limiter = $rate_limiter ?? new RateLimiter();
	}

	/**
	 * Route a request to the appropriate handler.
	 *
	 * @param string $method The MCP method name.
	 * @param array  $params The request parameters.
	 * @param mixed  $request_id The request ID (for JSON-RPC) - string, number, or null.
	 * @param string $transport_name Transport name for observability.
	 * @param \WickedEvolutions\McpAdapter\Transport\Infrastructure\HttpRequestContext|null $http_context HTTP context for session management.
	 *
	 * @return array
	 */
	public function route_request( string $method, array $params, $request_id = 0, string $transport_name = 'unknown', ?HttpRequestContext $http_context = null ): array {
		// Track request start time.
		$start_time = microtime( true );

		// Common tags for all metrics.
		$common_tags = array(
			'method'     => $method,
			'transport'  => $transport_name,
			'server_id'  => $this->context->mcp_server->get_server_id(),
			'params'     => $this->sanitize_params_for_logging( $params ),
			'request_id' => $request_id,
			'session_id' => $http_context ? $http_context->session_id : null,
		);

		$handlers = array(
			'initialize'          => fn() => $this->handle_initialize_with_session( $params, $request_id, $http_context ),
			'ping'                => fn() => $this->context->system_handler->ping( $request_id ),
			'tools/list'          => fn() => $this->context->tools_handler->list_tools( $request_id ),
			'tools/list/all'      => fn() => $this->context->tools_handler->list_all_tools( $request_id ),
			'tools/call'          => fn() => $this->context->tools_handler->call_tool( $params, $request_id ),
			'resources/list'      => fn() => $this->add_cursor_compatibility( $this->context->resources_handler->list_resources( $request_id ) ),
			'resources/read'      => fn() => $this->context->resources_handler->read_resource( $params, $request_id ),
			'prompts/list'        => fn() => $this->context->prompts_handler->list_prompts( $request_id ),
			'prompts/get'         => fn() => $this->context->prompts_handler->get_prompt( $params, $request_id ),
			'logging/setLevel'    => fn() => $this->context->system_handler->set_logging_level( $params, $request_id ),
			'completion/complete' => fn() => $this->context->system_handler->complete( $request_id ),
			'roots/list'          => fn() => $this->context->system_handler->list_roots( $request_id ),
		);

		// Rate-limit gate — runs after auth resolves, before handler dispatch.
		// `initialize` is exempted so a brand-new client can always negotiate.
		if ( 'initialize' !== $method ) {
			$rate_limit_result = $this->apply_rate_limit( $method, $request_id, $common_tags, $start_time, $http_context );
			if ( null !== $rate_limit_result ) {
				return $rate_limit_result;
			}
		}

		try {
			$result = isset( $handlers[ $method ] ) ? $handlers[ $method ]() : $this->create_method_not_found_error( $method );

			// Calculate request duration.
			$duration = ( microtime( true ) - $start_time ) * 1000; // Convert to milliseconds.

			// Extract metadata from handler response (if present).
			$metadata = $result['_metadata'] ?? array();
			unset( $result['_metadata'] ); // Don't send to client.

			// Capture newly created session ID from initialize if present.
			if ( isset( $result['_session_id'] ) ) {
				$metadata['new_session_id'] = $result['_session_id'];
			}

			// Merge common tags with handler metadata.
			$tags = array_merge( $common_tags, $metadata );

			// Determine status and record event.
			// A protocol error envelope has an 'error' key with both 'code' (int) and 'message' (string).
			// This guards against misclassifying legitimate ability results that happen to contain an 'error' key.
			$is_protocol_error = isset( $result['error']['code'], $result['error']['message'] )
				&& is_int( $result['error']['code'] )
				&& is_string( $result['error']['message'] );

			if ( $is_protocol_error ) {
				$tags['status']     = 'error';
				$tags['error_code'] = $result['error']['code'];
				$this->context->observability_handler->record_event( 'mcp.request', $tags, $duration );

				return $result;
			}

			// Successful request.
			$tags['status'] = 'success';
			$this->context->observability_handler->record_event( 'mcp.request', $tags, $duration );

			return $result;
		} catch ( \Throwable $exception ) {
			// Calculate request duration.
			$duration = ( microtime( true ) - $start_time ) * 1000; // Convert to milliseconds.

			// Track exception with categorization.
			$tags = array_merge(
				$common_tags,
				array(
					'status'         => 'error',
					'error_type'     => get_class( $exception ),
					'error_category' => $this->categorize_error( $exception ),
				)
			);
			$this->context->observability_handler->record_event( 'mcp.request', $tags, $duration );

			// Create error response from exception.
			return array( 'error' => McpErrorFactory::internal_error( $request_id, 'Handler error occurred' )['error'] );
		}
	}

	/**
	 * Run the rate limiter and, on deny, emit the boundary event and return
	 * the JSON-RPC error envelope. Returns null when the request is allowed.
	 *
	 * @param string $method
	 * @param mixed  $request_id
	 * @param array  $common_tags
	 * @param float  $start_time
	 * @param \WickedEvolutions\McpAdapter\Transport\Infrastructure\HttpRequestContext|null $http_context
	 * @return array|null
	 */
	private function apply_rate_limit( string $method, $request_id, array $common_tags, float $start_time, ?HttpRequestContext $http_context ): ?array {
		$server_array = isset( $_SERVER ) && is_array( $_SERVER ) ? $_SERVER : array();
		$client_ip    = TrustedProxyResolver::resolve( $server_array );
		$user_id      = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		$server_id    = $this->context->mcp_server->get_server_id();
		$site_key     = RateLimiter::build_site_key( $server_id );

		$client_name = '';
		if ( isset( $common_tags['params']['client_name'] ) && is_string( $common_tags['params']['client_name'] ) ) {
			$client_name = $common_tags['params']['client_name'];
		}

		$tags_for_filter = array(
			'method'      => $method,
			'user_id'     => $user_id,
			'session_id'  => $http_context ? $http_context->session_id : null,
			'client_name' => $client_name,
		);

		$verdict = $this->rate_limiter->check( $method, $client_ip, $user_id, $site_key, $tags_for_filter );

		if ( ( $verdict[0] ?? '' ) !== 'deny' ) {
			return null;
		}

		$retry_after = (int) ( $verdict[1] ?? 1 );
		$reason      = (string) ( $verdict[2] ?? 'rate_limited' );
		$dimension   = (string) ( $verdict[3] ?? RateLimiter::DIMENSION_IP );
		$limit       = (int) ( $verdict[4] ?? 0 );
		$window      = (int) ( $verdict[5] ?? 0 );

		$retry_after_ms = $retry_after * 1000;

		$error = McpErrorFactory::rate_limited( $request_id, $retry_after_ms, $limit, $window, $dimension );

		// Boundary event — sanitized, PII-safe.
		$boundary_tags = array(
			'severity'       => 'warn',
			'method'         => $method,
			'session_id'     => $http_context ? $http_context->session_id : null,
			'client_name'    => $client_name,
			'user_id'        => $user_id,
			'ip'             => TrustedProxyResolver::truncate_for_log( $client_ip ),
			'reason'         => $reason,
			'dimension'      => $dimension,
			'limit'          => $limit,
			'window'         => $window,
			'retry_after_ms' => $retry_after_ms,
			'status_code'    => 429,
			'transport'      => $common_tags['transport'] ?? 'unknown',
			'error_code'     => McpErrorFactory::RATE_LIMITED,
		);
		BoundaryEventEmitter::emit( $this->context->observability_handler, 'boundary.rate_limit_hit', $boundary_tags );

		// Observability — record the short-circuit so dashboards still see it.
		$duration = ( microtime( true ) - $start_time ) * 1000;
		$tags     = array_merge(
			$common_tags,
			array(
				'status'         => 'error',
				'error_code'     => McpErrorFactory::RATE_LIMITED,
				'dimension'      => $dimension,
				'limit'          => $limit,
				'window'         => $window,
				'retry_after_ms' => $retry_after_ms,
			)
		);
		$this->context->observability_handler->record_event( 'mcp.request', $tags, $duration );

		return array( 'error' => $error['error'] );
	}

	/**
	 * Add nextCursor for backward compatibility with existing API.
	 *
	 * @param array $result The result array.
	 * @return array
	 */
	public function add_cursor_compatibility( array $result ): array {
		if ( ! isset( $result['nextCursor'] ) ) {
			$result['nextCursor'] = '';
		}

		return $result;
	}

	/**
	 * Handle initialize requests with session management.
	 *
	 * @param array $params The request parameters.
	 * @param mixed $request_id The request ID.
	 * @param \WickedEvolutions\McpAdapter\Transport\Infrastructure\HttpRequestContext|null $http_context HTTP context for session management.
	 * @return array
	 */
	private function handle_initialize_with_session( array $params, $request_id, ?HttpRequestContext $http_context ): array {
		// Get the initialize response from the handler
		$result = $this->context->initialize_handler->handle( $params, $request_id );

		// Handle session creation if HTTP context is provided and initialize was successful
		if ( $http_context && ! isset( $result['error'] ) && ! $http_context->session_id ) {
			$session_result = HttpSessionValidator::create_session( $params );

			// create_session now returns array{session_id, session_token} on success or an error array.
			// Distinguish by checking for the McpErrorFactory error structure (code + message keys).
			$is_error = isset( $session_result['error']['code'], $session_result['error']['message'] )
				|| isset( $session_result['code'], $session_result['message'] );

			if ( $is_error ) {
				// Session creation failed — propagate error.
				return array( 'error' => $session_result['error'] ?? $session_result );
			}

			// Store session ID and token in result for HttpRequestHandler to add as response headers.
			$result['_session_id']    = $session_result['session_id'];
			$result['_session_token'] = $session_result['session_token'];
		}

		return $result;
	}

	/**
	 * Create a method not found error with generic format.
	 *
	 * @param string $method The method that was not found.
	 * @return array
	 */
	private function create_method_not_found_error( string $method ): array {
		return array(
			'error' => McpErrorFactory::method_not_found( 0, $method )['error'],
		);
	}

	/**
	 * Categorize an exception into a general error category.
	 *
	 * @param \Throwable $exception The exception to categorize.
	 *
	 * @return string
	 */
	private function categorize_error( \Throwable $exception ): string {
		$error_categories = array(
			\ArgumentCountError::class       => 'arguments',
			\Error::class                    => 'system',
			\InvalidArgumentException::class => 'validation',
			\LogicException::class           => 'logic',
			\RuntimeException::class         => 'execution',
			\TypeError::class                => 'type',
		);

		return $error_categories[ get_class( $exception ) ] ?? 'unknown';
	}

	/**
	 * Sanitize request params for logging to remove sensitive data and limit size.
	 *
	 * @param array $params The request parameters to sanitize.
	 *
	 * @return array Sanitized parameters safe for logging.
	 */
	private function sanitize_params_for_logging( array $params ): array {
		// Return early for empty parameters.
		if ( empty( $params ) ) {
			return array();
		}

		$sanitized = array();

		// Extract only safe, useful fields for observability
		$safe_fields = array( 'name', 'protocolVersion', 'uri' );

		foreach ( $safe_fields as $field ) {
			if ( ! isset( $params[ $field ] ) || ! is_scalar( $params[ $field ] ) ) {
				continue;
			}

			$sanitized[ $field ] = $params[ $field ];
		}

		// Add clientInfo name if available (useful for debugging)
		if ( isset( $params['clientInfo']['name'] ) ) {
			$sanitized['client_name'] = $params['clientInfo']['name'];
		}

		// Add arguments count for tool calls (but not the actual arguments to avoid logging sensitive data)
		if ( isset( $params['arguments'] ) && is_array( $params['arguments'] ) ) {
			$sanitized['arguments_count'] = count( $params['arguments'] );
			$sanitized['arguments_keys']  = array_keys( $params['arguments'] );
		}

		return $sanitized;
	}
}
