<?php
/**
 * Response redactor — runs at the adapter response boundary.
 *
 * Recursive, type-aware substitution. Three buckets:
 *   - Bucket 1 (secrets): always-on, never disabled.
 *   - Bucket 2 (payment / regulated IDs): default-on, master-toggle gated.
 *   - Bucket 3 (contact PII / access labels): default-on, master-toggle gated.
 *
 * Matching rules:
 *   - Field-name match is case-insensitive against the canonical keyword lists.
 *   - When a field name matches, the ENTIRE value at that key is replaced (recursively
 *     untouched — the subtree is redacted as a whole using a type-shape-preserving marker).
 *   - When a field name does NOT match, traversal recurses into arrays/objects and the
 *     scalar leaf is checked against Bucket 1 / Bucket 2 pattern matchers (hash formats,
 *     known API-key prefixes, Luhn-valid PANs). Patterns NEVER run on free-text bodies as
 *     a regex over the serialised JSON — they apply per-scalar-string only.
 *
 * Hard limits:
 *   - Max depth 64
 *   - Max nodes 100,000
 * Exceeding either raises {@see RedactionLimitExceeded}, which the caller MUST translate
 * to a transport-level error rather than returning a partially-redacted response.
 *
 * Filter hooks:
 *   - `abilities_mcp_redaction_keywords` — modify Bucket 3 keyword list.
 *   - `abilities_mcp_redaction_master_enabled` — modify master toggle.
 *   - `abilities_mcp_redacted_value` — `(value, field_name, bucket_number)` → custom marker.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Infrastructure\Redaction;

/**
 * Boundary redactor.
 */
final class ResponseRedactor {

	public const MAX_DEPTH = 64;
	public const MAX_NODES = 100000;

	public const FILTER_REDACTED_VALUE = 'abilities_mcp_redacted_value';

	/**
	 * Lower-case Bucket 1 keyword set (key => true) for O(1) lookup.
	 *
	 * @var array<string,bool>
	 */
	private array $bucket1_set;

	/**
	 * Lower-case Bucket 2 keyword set.
	 *
	 * @var array<string,bool>
	 */
	private array $bucket2_set;

	/**
	 * Lower-case Bucket 3 keyword set.
	 *
	 * @var array<string,bool>
	 */
	private array $bucket3_set;

	/**
	 * Whether Bucket 2 is active for this response (master + per-ability exemption).
	 *
	 * @var bool
	 */
	private bool $bucket2_active;

	/**
	 * Whether Bucket 3 is active for this response (master + per-ability exemption).
	 *
	 * @var bool
	 */
	private bool $bucket3_active;

	/**
	 * Per-bucket counters for the most recent {@see redact()} call.
	 *
	 * @var array<int,int>
	 */
	private array $counts = array();

	/**
	 * Node counter for the most recent {@see redact()} call.
	 *
	 * @var int
	 */
	private int $node_count = 0;

	/**
	 * Build a redactor configured for the given ability call.
	 *
	 * @param string|null $ability_name Ability name (e.g. `users/list`), or null when method has no ability.
	 */
	public function __construct( ?string $ability_name = null ) {
		$this->bucket1_set = self::flip_lower( RedactionConfig::bucket1_keywords() );
		$this->bucket2_set = self::flip_lower( RedactionConfig::bucket2_keywords() );
		$this->bucket3_set = self::flip_lower( RedactionConfig::bucket3_keywords() );

		$master                = RedactionConfig::is_master_enabled();
		$this->bucket2_active  = $master && ! RedactionConfig::is_ability_exempt( $ability_name, RedactionConfig::BUCKET_PAYMENT );
		$this->bucket3_active  = $master && ! RedactionConfig::is_ability_exempt( $ability_name, RedactionConfig::BUCKET_CONTACT );
	}

	/**
	 * Redact a response body. Returns the redacted copy.
	 *
	 * @param array $response Response body to redact.
	 *
	 * @return array
	 *
	 * @throws RedactionLimitExceeded When max depth or max nodes is exceeded.
	 */
	public function redact( array $response ): array {
		$this->counts     = array(
			RedactionConfig::BUCKET_SECRETS => 0,
			RedactionConfig::BUCKET_PAYMENT => 0,
			RedactionConfig::BUCKET_CONTACT => 0,
		);
		$this->node_count = 0;

		return $this->walk_array( $response, 0, null );
	}

	/**
	 * Redacted-value counts from the most recent redaction (per bucket).
	 *
	 * @return array{1:int,2:int,3:int}
	 */
	public function get_counts(): array {
		return array(
			RedactionConfig::BUCKET_SECRETS => $this->counts[ RedactionConfig::BUCKET_SECRETS ] ?? 0,
			RedactionConfig::BUCKET_PAYMENT => $this->counts[ RedactionConfig::BUCKET_PAYMENT ] ?? 0,
			RedactionConfig::BUCKET_CONTACT => $this->counts[ RedactionConfig::BUCKET_CONTACT ] ?? 0,
		);
	}

	/**
	 * Walk an array. Each element is checked against keyword set first; on miss,
	 * the value is recursed (for arrays/objects) or pattern-checked (for scalar strings).
	 *
	 * @param array       $arr   Array node.
	 * @param int         $depth Current depth.
	 * @param string|null $key   Parent key, or null at the root.
	 *
	 * @return array
	 *
	 * @throws RedactionLimitExceeded
	 */
	private function walk_array( array $arr, int $depth, ?string $key ): array {
		if ( $depth > self::MAX_DEPTH ) {
			throw new RedactionLimitExceeded( 'max_depth_exceeded' );
		}

		$out = array();
		foreach ( $arr as $k => $v ) {
			if ( ++$this->node_count > self::MAX_NODES ) {
				throw new RedactionLimitExceeded( 'max_nodes_exceeded' );
			}

			$out[ $k ] = is_string( $k )
				? $this->process_named_field( $k, $v, $depth + 1 )
				: $this->process_value( $v, $depth + 1, null );
		}
		return $out;
	}

	/**
	 * Apply field-name matching to a string-keyed entry. On hit, redact the whole subtree.
	 *
	 * @param string $key   Field name.
	 * @param mixed  $value Field value.
	 * @param int    $depth Current depth (for the value; the key itself is at depth-1).
	 *
	 * @return mixed
	 *
	 * @throws RedactionLimitExceeded
	 */
	private function process_named_field( string $key, $value, int $depth ) {
		$lower = strtolower( $key );

		if ( isset( $this->bucket1_set[ $lower ] ) ) {
			$this->counts[ RedactionConfig::BUCKET_SECRETS ]++;
			return $this->build_marker( $value, $key, RedactionConfig::BUCKET_SECRETS );
		}

		if ( $this->bucket2_active && isset( $this->bucket2_set[ $lower ] ) ) {
			$this->counts[ RedactionConfig::BUCKET_PAYMENT ]++;
			return $this->build_marker( $value, $key, RedactionConfig::BUCKET_PAYMENT );
		}

		if ( $this->bucket3_active && isset( $this->bucket3_set[ $lower ] ) ) {
			$this->counts[ RedactionConfig::BUCKET_CONTACT ]++;
			return $this->build_marker( $value, $key, RedactionConfig::BUCKET_CONTACT );
		}

		return $this->process_value( $value, $depth, $key );
	}

	/**
	 * Process a value: recurse into containers, apply pattern matchers to scalar strings.
	 *
	 * @param mixed       $value Value to process.
	 * @param int         $depth Current depth.
	 * @param string|null $key   Parent field name (string keys only) or null.
	 *
	 * @return mixed
	 *
	 * @throws RedactionLimitExceeded
	 */
	private function process_value( $value, int $depth, ?string $key ) {
		if ( is_array( $value ) ) {
			return $this->walk_array( $value, $depth, $key );
		}

		if ( is_object( $value ) ) {
			$as_array = (array) $value;
			$walked   = $this->walk_array( $as_array, $depth, $key );
			return (object) $walked;
		}

		if ( is_string( $value ) ) {
			return $this->maybe_redact_scalar_string( $value, $key );
		}

		return $value;
	}

	/**
	 * Apply Bucket 1 / Bucket 2 pattern matchers to a scalar string.
	 *
	 * Patterns NEVER apply to free-text-style fields when the field name itself was
	 * already known and exempted via traversal — only to scalars whose containing key
	 * was not bucketed. Bucket 1 patterns always run; Bucket 2 patterns only when active.
	 *
	 * Bucket 3 has no pattern matcher (the brief excludes contact-PII heuristic detection
	 * to keep blog/comment bodies untouched).
	 *
	 * @param string      $value Scalar string value.
	 * @param string|null $key   Containing field name (or null at array root).
	 *
	 * @return mixed
	 */
	private function maybe_redact_scalar_string( string $value, ?string $key ) {
		if ( PatternMatchers::is_password_hash( $value ) || PatternMatchers::is_known_api_key( $value ) ) {
			$this->counts[ RedactionConfig::BUCKET_SECRETS ]++;
			return $this->build_marker( $value, $key ?? '', RedactionConfig::BUCKET_SECRETS );
		}

		if ( $this->bucket2_active && PatternMatchers::passes_luhn( $value ) ) {
			$this->counts[ RedactionConfig::BUCKET_PAYMENT ]++;
			return $this->build_marker( $value, $key ?? '', RedactionConfig::BUCKET_PAYMENT );
		}

		return $value;
	}

	/**
	 * Build a redaction marker that preserves the original value's shape.
	 *
	 * Type rules:
	 *   - string  → "[redacted:bucket_N]"
	 *   - number  → null (preserves nullable schema slot)
	 *   - bool    → original value (booleans are not in any bucket)
	 *   - object  → {"redacted": true, "reason": "bucket_N"}
	 *   - array   → ["[redacted:bucket_N]"]
	 *   - null    → null (no marker)
	 *
	 * Caller can override via `abilities_mcp_redacted_value` filter.
	 *
	 * @param mixed  $value      Original value.
	 * @param string $field_name Field name (informational; passed to filter).
	 * @param int    $bucket     Bucket constant.
	 *
	 * @return mixed
	 */
	private function build_marker( $value, string $field_name, int $bucket ) {
		$default = $this->default_marker( $value, $bucket );

		if ( function_exists( 'apply_filters' ) ) {
			return apply_filters( self::FILTER_REDACTED_VALUE, $default, $field_name, $bucket );
		}

		return $default;
	}

	/**
	 * Default marker for the given value type and bucket.
	 *
	 * @param mixed $value
	 * @param int   $bucket
	 * @return mixed
	 */
	private function default_marker( $value, int $bucket ) {
		$tag = 'bucket_' . $bucket;

		if ( null === $value ) {
			return null;
		}
		if ( is_bool( $value ) ) {
			return $value;
		}
		if ( is_int( $value ) || is_float( $value ) ) {
			return null;
		}
		if ( is_string( $value ) ) {
			return '[redacted:' . $tag . ']';
		}
		if ( is_array( $value ) ) {
			return array( '[redacted:' . $tag . ']' );
		}
		if ( is_object( $value ) ) {
			return (object) array(
				'redacted' => true,
				'reason'   => $tag,
			);
		}
		return '[redacted:' . $tag . ']';
	}

	/**
	 * Lower-case + flip a list of keywords into a hash-set for O(1) lookup.
	 *
	 * @param string[] $keywords
	 * @return array<string,bool>
	 */
	private static function flip_lower( array $keywords ): array {
		$out = array();
		foreach ( $keywords as $kw ) {
			if ( ! is_string( $kw ) || '' === $kw ) {
				continue;
			}
			$out[ strtolower( $kw ) ] = true;
		}
		return $out;
	}
}
