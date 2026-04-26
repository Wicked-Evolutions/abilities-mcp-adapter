<?php
/**
 * Adapter-layer gate that runs the redaction filter at the response boundary.
 *
 * Both HTTP and stdio transports route through {@see RequestRouter::route_request()}
 * and then format the result as JSON-RPC. This gate sits between those two steps —
 * it inspects the resolved method and ability name, runs {@see ResponseRedactor}
 * over the success body, and (if an observability handler is wired) emits
 * `boundary.redaction_applied` with per-bucket counts.
 *
 * The gate never mutates protocol-error envelopes (`{"error": {...}}`) — only the
 * success result body is filtered. Errors are already plain-text strings or
 * structured codes, never response payload data.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Infrastructure\Redaction;

use WickedEvolutions\McpAdapter\Infrastructure\ErrorHandling\McpErrorFactory;
use WickedEvolutions\McpAdapter\Infrastructure\Observability\BoundaryEventEmitter;
use WickedEvolutions\McpAdapter\Infrastructure\Observability\Contracts\McpObservabilityHandlerInterface;

/**
 * Gate that applies redaction at the adapter response boundary.
 */
final class ResponseRedactionGate {

	/**
	 * Apply redaction to a router result, in place of the router's return value.
	 *
	 * On success: returns the redacted result (same shape).
	 * On limit exceeded: returns an internal-error envelope (better to fail closed
	 *   than leak a partial response).
	 *
	 * Pass-through cases (no redaction):
	 *   - Result already contains a JSON-RPC error envelope.
	 *   - Result is empty.
	 *
	 * @param array                                  $result        Router result (possibly containing _session_id/_session_token).
	 * @param string                                 $method        JSON-RPC method (e.g. `tools/call`).
	 * @param array                                  $params        JSON-RPC params (used to extract ability name on tools/call).
	 * @param mixed                                  $request_id    Original request id (preserved on error).
	 * @param McpObservabilityHandlerInterface|null  $observability Optional handler for boundary events.
	 *
	 * @return array
	 */
	public static function apply( array $result, string $method, array $params, $request_id, ?McpObservabilityHandlerInterface $observability = null ): array {
		// Don't redact protocol error envelopes.
		if ( isset( $result['error']['code'], $result['error']['message'] )
			&& is_int( $result['error']['code'] )
			&& is_string( $result['error']['message'] )
		) {
			return $result;
		}

		// Extract internal session bookkeeping before redaction so the redactor
		// never sees them. Caller must restore them on the returned result.
		$session_id    = $result['_session_id'] ?? null;
		$session_token = $result['_session_token'] ?? null;
		$metadata      = $result['_metadata'] ?? null;
		unset( $result['_session_id'], $result['_session_token'], $result['_metadata'] );

		$ability_name = self::extract_ability_name( $method, $params );

		try {
			$redactor = new ResponseRedactor( $ability_name );
			$redacted = $redactor->redact( $result );
			$counts   = $redactor->get_counts();
		} catch ( RedactionLimitExceeded $e ) {
			self::emit_redaction_failure( $observability, $method, $ability_name, $e->getMessage() );
			return array(
				'error' => McpErrorFactory::internal_error( $request_id, 'Response too large to safely redact' )['error'],
			);
		}

		if ( null !== $session_id ) {
			$redacted['_session_id'] = $session_id;
		}
		if ( null !== $session_token ) {
			$redacted['_session_token'] = $session_token;
		}
		if ( null !== $metadata ) {
			$redacted['_metadata'] = $metadata;
		}

		$total = $counts[ RedactionConfig::BUCKET_SECRETS ]
			+ $counts[ RedactionConfig::BUCKET_PAYMENT ]
			+ $counts[ RedactionConfig::BUCKET_CONTACT ];

		if ( $total > 0 ) {
			self::emit_redaction_event( $observability, $method, $ability_name, $counts );
		}

		return $redacted;
	}

	/**
	 * Pull the ability name out of params for tools/call. Other methods have no ability scope.
	 *
	 * @param string $method
	 * @param array  $params
	 * @return string|null
	 */
	private static function extract_ability_name( string $method, array $params ): ?string {
		if ( 'tools/call' === $method && isset( $params['name'] ) && is_string( $params['name'] ) ) {
			return $params['name'];
		}
		return null;
	}

	/**
	 * Emit `boundary.redaction_applied` with per-bucket counts (no values).
	 *
	 * @param McpObservabilityHandlerInterface|null $handler
	 * @param string                                $method
	 * @param string|null                           $ability_name
	 * @param array<int,int>                        $counts
	 */
	private static function emit_redaction_event( ?McpObservabilityHandlerInterface $handler, string $method, ?string $ability_name, array $counts ): void {
		BoundaryEventEmitter::emit(
			$handler,
			'boundary.redaction_applied',
			array(
				'severity'           => 'info',
				'method'             => $method,
				'name'               => $ability_name ?? '',
				'redaction_count_b1' => $counts[ RedactionConfig::BUCKET_SECRETS ] ?? 0,
				'redaction_count_b2' => $counts[ RedactionConfig::BUCKET_PAYMENT ] ?? 0,
				'redaction_count_b3' => $counts[ RedactionConfig::BUCKET_CONTACT ] ?? 0,
			)
		);
	}

	/**
	 * Emit `boundary.transport.error` for redaction-guard failures.
	 *
	 * @param McpObservabilityHandlerInterface|null $handler
	 * @param string                                $method
	 * @param string|null                           $ability_name
	 * @param string                                $reason
	 */
	private static function emit_redaction_failure( ?McpObservabilityHandlerInterface $handler, string $method, ?string $ability_name, string $reason ): void {
		BoundaryEventEmitter::emit(
			$handler,
			'boundary.transport.error',
			array(
				'severity'   => 'warn',
				'method'     => $method,
				'name'       => $ability_name ?? '',
				'error_code' => 'redaction_' . $reason,
			)
		);
	}
}
