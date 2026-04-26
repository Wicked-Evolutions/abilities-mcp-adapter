<?php
/**
 * Adapter-side boundary event emitter.
 *
 * Single emission point for `boundary.*` events. Sanitizes tags against
 * the metadata-only allowlist (synthesis Decision 10) BEFORE invoking
 * either the typed observability handler or the third-party action hook.
 *
 * Listeners on `mcp_adapter_boundary_event` therefore never receive raw
 * params, response bodies, or sensitive values — even if a third-party
 * plugin author hopes for them. This is a hard contract.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Infrastructure\Observability;

use WickedEvolutions\McpAdapter\Infrastructure\Observability\Contracts\McpObservabilityHandlerInterface;

/**
 * Emit a sanitized boundary event through both the typed handler and
 * the `mcp_adapter_boundary_event` WordPress action.
 */
final class BoundaryEventEmitter {

	/**
	 * Allowlist of metadata-only fields permitted in boundary tags.
	 * Anything outside this list is dropped before emission.
	 *
	 * @var string[]
	 */
	private const TAG_ALLOWLIST = array(
		'severity',
		'ip',
		'user_id',
		'session_id',
		'api_key',
		'api_key_hash',
		'client_name',
		'user_agent',
		'method',
		'request_id',
		'transport',
		'status_code',
		'error_code',
		// detail_json builders (used by writer):
		'name',
		'protocolVersion',
		'uri',
		'arguments_count',
		'arguments_keys',
		'reason',
		'limit',
		'window',
		'dimension',
		'retry_after_ms',
		'batch_size',
		'body_size',
		// boundary.redaction_applied counters (per-bucket, values never included):
		'redaction_count_b1',
		'redaction_count_b2',
		'redaction_count_b3',
	);

	/**
	 * Emit a boundary event.
	 *
	 * @param McpObservabilityHandlerInterface|null $handler     Typed handler, or null.
	 * @param string                                $event       Event name (must start with `boundary.`).
	 * @param array                                 $tags        Raw tags. Sanitized before emission.
	 * @param float|null                            $duration_ms Optional duration.
	 *
	 * @return void
	 */
	public static function emit( ?McpObservabilityHandlerInterface $handler, string $event, array $tags = array(), ?float $duration_ms = null ): void {
		if ( strpos( $event, 'boundary.' ) !== 0 ) {
			return;
		}

		$sanitized = self::sanitize( $tags );

		// Path 1 — typed handler (if present and not the null one).
		if ( $handler ) {
			$handler->record_event( $event, $sanitized, $duration_ms );
		}

		// Path 2 — action hook for third-party listeners.
		if ( function_exists( 'do_action' ) ) {
			do_action( 'mcp_adapter_boundary_event', $event, $sanitized, $duration_ms );
		}
	}

	/**
	 * Filter tags down to allowlisted, scalar-or-scalar-array values.
	 *
	 * Defense-in-depth: callers should already pass metadata only, but we
	 * never trust upstream. Object/closure/resource values are dropped.
	 * Strings are length-capped.
	 *
	 * @param array $tags
	 * @return array
	 */
	public static function sanitize( array $tags ): array {
		$out = array();
		foreach ( self::TAG_ALLOWLIST as $key ) {
			if ( ! array_key_exists( $key, $tags ) ) {
				continue;
			}
			$value = $tags[ $key ];

			if ( is_string( $value ) ) {
				// Cap string length to keep tags compact.
				$out[ $key ] = strlen( $value ) > 512 ? substr( $value, 0, 512 ) : $value;
				continue;
			}
			if ( is_int( $value ) || is_float( $value ) || is_bool( $value ) || $value === null ) {
				$out[ $key ] = $value;
				continue;
			}
			if ( is_array( $value ) ) {
				$flat = array();
				foreach ( $value as $v ) {
					if ( is_scalar( $v ) ) {
						$flat[] = is_string( $v ) && strlen( $v ) > 512 ? substr( $v, 0, 512 ) : $v;
					}
				}
				$out[ $key ] = $flat;
			}
			// Anything else (objects, resources, closures): dropped.
		}

		return $out;
	}
}
