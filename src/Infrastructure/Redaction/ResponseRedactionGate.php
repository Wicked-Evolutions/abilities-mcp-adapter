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

		// `tools/call` responses ship two parallel channels:
		//   - structuredContent: the typed result tree (just redacted in place)
		//   - content[i].text:   a JSON-encoded snapshot of the SAME tree, captured
		//                        before redaction runs, so it still holds the raw
		//                        values. The keyword-based redactor only matches
		//                        field names — a serialized string slips through
		//                        unchanged. Regenerate the text channel from the
		//                        redacted tree to close the leak.
		//
		// Image responses (content[0].type === 'image') carry base64 binary in
		// `data`, no `text` field, no `structuredContent` — left untouched.
		// Text-only responses without `structuredContent` get a best-effort
		// JSON-decode/redact/re-encode so single-channel callers don't leak.
		$redacted = self::reconcile_tool_channels( $redacted, $redactor );

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
	 * Reconcile the dual response channels after redaction. See the call site
	 * for the leak this closes.
	 *
	 * Strategy:
	 *   - If `content[i].text` and a top-level `structuredContent` are both
	 *     present, the text channel is a stale JSON snapshot — re-encode the
	 *     (now redacted) `structuredContent` and stamp it into ALL text parts.
	 *     Stamping every text part rather than just `[0]` is defensive: the
	 *     adapter writes only `content[0].text` today, but a future
	 *     (or third-party) handler might emit several text parts derived
	 *     from the same structured payload.
	 *   - If `content[i].text` is present without `structuredContent`
	 *     (single-channel text response), best-effort redact the text in
	 *     place: JSON-decode, re-redact, re-encode. A non-JSON string is
	 *     left alone — keyword redaction has no field-name surface in a
	 *     free-form string.
	 *   - Image parts (`type === 'image'`) carry base64 binary in `data`,
	 *     not `text`; they are skipped.
	 *   - Anything that doesn't look like a tools/call response (no
	 *     `content` array, or no parts with a `text` key) is returned
	 *     unchanged. `initialize` and other non-tools/call results pass
	 *     through unaffected.
	 *
	 * @param array            $redacted Result with structuredContent already redacted.
	 * @param ResponseRedactor $redactor Reusable redactor for the per-text-part fallback.
	 * @return array
	 */
	private static function reconcile_tool_channels( array $redacted, ResponseRedactor $redactor ): array {
		if ( ! isset( $redacted['content'] ) || ! is_array( $redacted['content'] ) ) {
			return $redacted;
		}

		$has_structured     = array_key_exists( 'structuredContent', $redacted );
		$structured_payload = $has_structured ? $redacted['structuredContent'] : null;

		foreach ( $redacted['content'] as $i => $part ) {
			if ( ! is_array( $part ) ) {
				continue;
			}
			if ( isset( $part['type'] ) && 'text' !== $part['type'] ) {
				// Image / future binary parts — skip.
				continue;
			}
			if ( ! array_key_exists( 'text', $part ) ) {
				continue;
			}

			if ( $has_structured ) {
				// Canonical fix path: regenerate from the redacted typed payload.
				$encoded = function_exists( 'wp_json_encode' )
					? wp_json_encode( $structured_payload )
					: json_encode( $structured_payload );
				if ( false !== $encoded && null !== $encoded ) {
					$redacted['content'][ $i ]['text'] = $encoded;
				}
				continue;
			}

			// Single-channel text response: try JSON → redact → re-encode.
			$text = $part['text'];
			if ( ! is_string( $text ) || '' === $text ) {
				continue;
			}
			$decoded = json_decode( $text, true );
			if ( ! is_array( $decoded ) ) {
				// Plain text — keyword-based redaction has nothing to match.
				continue;
			}
			try {
				$redacted_decoded = $redactor->redact( $decoded );
			} catch ( RedactionLimitExceeded $e ) {
				// Best-effort path: a limit hit here shouldn't tear down the
				// whole response, but the original (potentially leaky) text
				// MUST NOT pass through. Replace with a safe marker.
				$redacted['content'][ $i ]['text'] = '[redacted:limit_exceeded]';
				continue;
			}
			$encoded = function_exists( 'wp_json_encode' )
				? wp_json_encode( $redacted_decoded )
				: json_encode( $redacted_decoded );
			if ( false !== $encoded && null !== $encoded ) {
				$redacted['content'][ $i ]['text'] = $encoded;
			}
		}

		return $redacted;
	}

	/**
	 * Pull the ability name out of params for tools/call. Other methods have no ability scope.
	 *
	 * Naming convention: the WordPress Abilities API stores ability names in
	 * **slash form** (e.g. `fluent-cart/list-customers`). MCP tool names cannot
	 * contain `/`, so {@see RegisterAbilityAsMcpTool::get_data()} converts
	 * `/` to `-` when advertising tools over the wire — `tools/call` therefore
	 * arrives with `params['name']` in **dash form** (e.g.
	 * `fluent-cart-list-customers`). Per-ability exemptions are stored against
	 * the slash form (canonical registry name), so any name the gate returns
	 * MUST be in slash form before reaching `is_ability_exempt()`.
	 *
	 * The adapter's primary AI-client path goes through the
	 * `mcp-adapter-execute-ability` meta-tool — `params['name']` is the
	 * meta-tool, the *real* ability lives at `params['arguments']['ability_name']`
	 * (which the operator typically passes in slash form already, but we
	 * still normalise defensively).
	 *
	 * `mcp-adapter-batch-execute` carries multiple inner abilities at
	 * `params['arguments']['requests'][i]['name']`. A single redaction pass
	 * over the outer response cannot honour per-ability exemptions for each
	 * inner result, so we return null — exemptions don't apply inside batch.
	 *
	 * @param string $method
	 * @param array  $params
	 * @return string|null Slash-form ability name suitable for exemption lookup, or null.
	 */
	private static function extract_ability_name( string $method, array $params ): ?string {
		if ( 'tools/call' !== $method ) {
			return null;
		}
		$outer = isset( $params['name'] ) && is_string( $params['name'] ) ? $params['name'] : '';
		if ( '' === $outer ) {
			return null;
		}

		// Meta-tool: `mcp-adapter-execute-ability` — unwrap to the inner ability.
		if ( 'mcp-adapter-execute-ability' === $outer || 'mcp-adapter/execute-ability' === $outer ) {
			$args = isset( $params['arguments'] ) && is_array( $params['arguments'] ) ? $params['arguments'] : array();
			if ( isset( $args['ability_name'] ) && is_string( $args['ability_name'] ) && '' !== $args['ability_name'] ) {
				return self::tool_name_to_ability_name( $args['ability_name'] );
			}
			return null;
		}

		// Meta-tool: `mcp-adapter-batch-execute` — multiple inner abilities, can't pick one.
		if ( 'mcp-adapter-batch-execute' === $outer || 'mcp-adapter/batch-execute' === $outer ) {
			return null;
		}

		// Direct tools/call against an ability registered as an MCP tool.
		// Outer name arrives in dash form — translate back to slash before lookup.
		return self::tool_name_to_ability_name( $outer );
	}

	/**
	 * Translate an MCP tool name (dash form, over-the-wire) to the canonical
	 * Abilities-API name (slash form, registry storage).
	 *
	 * Builds a dash→slash map from `wp_get_abilities()` once per request.
	 * If the input already contains a `/`, or doesn't match any registered
	 * ability, the input is returned unchanged — defensive fall-back so
	 * non-MCP code paths and unit-test contexts continue to work.
	 *
	 * @param string $tool_name
	 * @return string
	 */
	public static function tool_name_to_ability_name( string $tool_name ): string {
		if ( '' === $tool_name ) {
			return $tool_name;
		}
		// Already in slash form — registered abilities never contain a `/`
		// in their dash-form tool name, so a `/` means we already have the
		// canonical form.
		if ( false !== strpos( $tool_name, '/' ) ) {
			return $tool_name;
		}

		$map = self::dash_to_slash_map();
		return $map[ $tool_name ] ?? $tool_name;
	}

	/**
	 * Class-level cache for the dash→slash map. Built lazily on first lookup
	 * and lives for the duration of the request. Tests can reset it via
	 * {@see reset_name_cache_for_testing()}.
	 *
	 * @var array<string,string>|null
	 */
	private static ?array $dash_to_slash_cache = null;

	/**
	 * Build (and cache) a dash→slash lookup of every registered ability.
	 * Empty when `wp_get_abilities()` is unavailable (e.g. unit-test
	 * contexts without the WP Abilities API loaded).
	 *
	 * @return array<string,string>
	 */
	private static function dash_to_slash_map(): array {
		if ( null !== self::$dash_to_slash_cache ) {
			return self::$dash_to_slash_cache;
		}

		$cache = array();

		if ( ! function_exists( 'wp_get_abilities' ) ) {
			self::$dash_to_slash_cache = $cache;
			return $cache;
		}

		$abilities = wp_get_abilities();
		if ( ! is_array( $abilities ) && ! ( $abilities instanceof \Traversable ) ) {
			self::$dash_to_slash_cache = $cache;
			return $cache;
		}

		foreach ( $abilities as $ability ) {
			if ( ! is_object( $ability ) || ! method_exists( $ability, 'get_name' ) ) {
				continue;
			}
			$slash = (string) $ability->get_name();
			if ( '' === $slash ) {
				continue;
			}
			$dash = str_replace( '/', '-', $slash );
			// First-write wins — duplicate dash forms from differently-named
			// abilities should not silently rewrite an earlier registration.
			if ( ! isset( $cache[ $dash ] ) ) {
				$cache[ $dash ] = $slash;
			}
		}

		self::$dash_to_slash_cache = $cache;
		return $cache;
	}

	/**
	 * Reset the dash→slash cache so the next lookup rebuilds it from the
	 * current ability registry. Test-only.
	 *
	 * @internal
	 */
	public static function reset_name_cache_for_testing(): void {
		self::$dash_to_slash_cache = null;
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
