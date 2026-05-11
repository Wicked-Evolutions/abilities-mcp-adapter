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
 *   - Bucket 3 also runs an email-family token matcher (issue #103). Any field key
 *     whose tokens (split on `_`, `-`, camelCase boundaries) include `email` is
 *     redacted — `admin_email`, `author_email`, `billingEmail`, `to_email`, etc.
 *     The substring rule is intentionally scoped to the `email` family only;
 *     phone / address generalisation is contract-polish work.
 *   - Schema-metadata paths (`input_schema`/`output_schema` in the WP REST
 *     shape, `inputSchema`/`outputSchema` in the MCP wire shape) are exempt
 *     from redaction (issue #105 for the per-ability meta-tool path,
 *     completed by issue #113 for the method-level `tools/list` and
 *     `tools/list/all` paths). Their subtrees describe ability shape, not
 *     data, so running keyword/substring matching over property names like
 *     `email`, `username`, `password` would corrupt the cold-AI contract.
 *     The exemption is path-aware — only the literal schema-metadata keys
 *     trigger pass-through; field-name matching resumes below them only when
 *     the same names appear OUTSIDE a schema subtree.
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
	 * Whether the schema-metadata path exemption (issues #105 + #113) is
	 * active for this redactor instance. Set when either:
	 *   - the ability that produced the response is one of the dispatcher
	 *     meta-tools that returns ability schemas as structural metadata
	 *     (per {@see SCHEMA_METADATA_ABILITIES}, issue #105); or
	 *   - the JSON-RPC method is one of the schema-emit metadata methods
	 *     that lists tool schemas as the response payload itself (per
	 *     {@see SCHEMA_METADATA_METHODS}, issue #113).
	 *
	 * @var bool
	 */
	private bool $schema_metadata_exempt;

	/**
	 * Adapter meta-abilities whose responses describe ability shape (schemas)
	 * rather than carry runtime data. Issue #105 — `input_schema`/`output_schema`
	 * keys in these responses pass through redaction unchanged. Slash-form
	 * canonical names; the adapter routes both meta-tool wrappers and direct
	 * tools/call against these abilities through {@see ResponseRedactionGate}.
	 *
	 * Path-aware (response originates from a meta-ability) AND schema-aware
	 * (the literal `input_schema`/`output_schema` key) are both required —
	 * an arbitrary `meta/list-post-meta` response that happens to contain a
	 * key named `input_schema` is NOT exempt, so PII smuggled through user
	 * meta cannot bypass redaction.
	 */
	private const SCHEMA_METADATA_ABILITIES = array(
		'mcp-adapter/get-ability-info',
		'mcp-adapter/discover-abilities',
	);

	/**
	 * JSON-RPC methods whose response body IS the tool-schema catalog —
	 * the MCP protocol's tool-discovery surface. Each tool entry carries
	 * `inputSchema` / `outputSchema` (camelCase, MCP wire shape) describing
	 * the registered ability's WordPress-native schema. Walking redaction
	 * across these keys corrupts the schemas Anthropic / OpenAI / generic
	 * draft-2020-12 validators check at tool-load time (issue #113 —
	 * completes the #105 exemption pattern for the method-level path).
	 *
	 * Audit pattern: any future MCP method that emits schemas as its
	 * response payload (e.g. a hypothetical `tools/get-info`, or new
	 * MCP protocol additions) registers itself here explicitly rather
	 * than relying on a blanket method-level pass-through.
	 */
	private const SCHEMA_METADATA_METHODS = array(
		'tools/list',
		'tools/list/all',
	);

	/**
	 * Build a redactor configured for the given ability call.
	 *
	 * @param string|null $ability_name Ability name (e.g. `users/list`), or null when method has no ability.
	 * @param string|null $method       JSON-RPC method (e.g. `tools/list`), or null when unknown / unit-test contexts.
	 */
	public function __construct( ?string $ability_name = null, ?string $method = null ) {
		$this->bucket1_set = self::flip_lower( RedactionConfig::bucket1_keywords() );
		$this->bucket2_set = self::flip_lower( RedactionConfig::bucket2_keywords() );
		$this->bucket3_set = self::flip_lower( RedactionConfig::bucket3_keywords() );

		$master                = RedactionConfig::is_master_enabled();
		$this->bucket2_active  = $master && ! RedactionConfig::is_ability_exempt( $ability_name, RedactionConfig::BUCKET_PAYMENT );
		$this->bucket3_active  = $master && ! RedactionConfig::is_ability_exempt( $ability_name, RedactionConfig::BUCKET_CONTACT );

		$ability_is_schema_meta = null !== $ability_name
			&& in_array( $ability_name, self::SCHEMA_METADATA_ABILITIES, true );
		$method_is_schema_meta  = null !== $method
			&& in_array( $method, self::SCHEMA_METADATA_METHODS, true );

		$this->schema_metadata_exempt = $ability_is_schema_meta || $method_is_schema_meta;
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
	 * Order of checks is load-bearing:
	 *   1. Bucket 1 keyword (secrets — always wins, even inside schema metadata).
	 *   2. Schema-metadata exemption — `input_schema` / `output_schema` keys
	 *      pass through verbatim (issue #105). The subtree describes ability
	 *      shape; running keyword/substring matching over property names there
	 *      corrupts the schema contract every AI client depends on. Bucket 1
	 *      stays above this line because a (highly-unlikely) ability that
	 *      stores a literal secret named e.g. `password` next to a sibling
	 *      `input_schema` must still redact the secret. The exemption only
	 *      protects the schema subtree itself — schema-named keys at the
	 *      top level — not arbitrary keys nested below.
	 *   3. Bucket 2 / Bucket 3 exact-match keyword.
	 *   4. Bucket 3 email-family token match — any field whose tokens include
	 *      `email` (issue #103: `admin_email`, `author_email`, `billingEmail`,
	 *      `to_email`, etc.). Substring expansion is intentionally scoped to
	 *      the `email` family only; phone / address generalisation is
	 *      contract-polish work.
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

		if ( $this->schema_metadata_exempt && self::is_schema_metadata_key( $lower ) ) {
			$this->count_subtree_safe( $value, $depth );
			return $value;
		}

		if ( $this->bucket2_active && isset( $this->bucket2_set[ $lower ] ) ) {
			$this->counts[ RedactionConfig::BUCKET_PAYMENT ]++;
			return $this->build_marker( $value, $key, RedactionConfig::BUCKET_PAYMENT );
		}

		if ( $this->bucket3_active && isset( $this->bucket3_set[ $lower ] ) ) {
			$this->counts[ RedactionConfig::BUCKET_CONTACT ]++;
			return $this->build_marker( $value, $key, RedactionConfig::BUCKET_CONTACT );
		}

		if ( $this->bucket3_active && self::is_email_family_token( $key ) ) {
			$this->counts[ RedactionConfig::BUCKET_CONTACT ]++;
			return $this->build_marker( $value, $key, RedactionConfig::BUCKET_CONTACT );
		}

		return $this->process_value( $value, $depth, $key );
	}

	/**
	 * Whether the lower-cased key denotes a schema-metadata subtree exempt
	 * from redaction (issues #105 + #113).
	 *
	 * Scoped tightly to the WordPress Abilities API schema fields in BOTH
	 * naming conventions the suite traverses: snake_case (`input_schema` /
	 * `output_schema`) as emitted by the WP-REST shape — meta-ability
	 * responses like `mcp-adapter/get-ability-info` — AND camelCase
	 * (`inputSchema` / `outputSchema`) as emitted by the MCP wire shape —
	 * the `tools/list` / `tools/list/all` JSON-RPC method payloads in
	 * {@see \WickedEvolutions\McpAdapter\Handlers\Tools\ToolsHandler}. Both
	 * forms describe the same registered ability schema; treating them
	 * symmetrically is the projection-layer contract.
	 *
	 * The key-name check fires only when the redactor was constructed in a
	 * schema-metadata context (see {@see SCHEMA_METADATA_ABILITIES} /
	 * {@see SCHEMA_METADATA_METHODS}). Outside those contexts a runtime
	 * payload happening to use one of these key names still redacts.
	 *
	 * Broader dispatcher-metadata exemption (e.g. `properties.<*>.description`,
	 * `properties.<*>.example`) is contract-polish work.
	 */
	private static function is_schema_metadata_key( string $lower_key ): bool {
		return 'input_schema' === $lower_key
			|| 'output_schema' === $lower_key
			|| 'inputschema' === $lower_key
			|| 'outputschema' === $lower_key;
	}

	/**
	 * Token-based email-family detector (issue #103).
	 *
	 * Splits the field name on snake (`_`), kebab (`-`), and camelCase
	 * boundaries; returns true when any token, lower-cased, equals `email`.
	 * Catches `email`, `admin_email`, `author_email`, `network_admin_email`,
	 * `to_email`, `from_email`, `customer_email`, `user_email`,
	 * `billingEmail`, etc. Does NOT catch unrelated tokens like `emailable`
	 * or `emails` (the matcher is exact-token, not substring within a token).
	 *
	 * Path-aware allowlist exceptions live above (schema-metadata exemption);
	 * there is no broad field-name allowlist here on purpose — runtime values
	 * named `admin_email` / `author_email` / `customer_email` etc. must redact
	 * unconditionally per the alpha-gate acceptance contract.
	 */
	private static function is_email_family_token( string $key ): bool {
		$tokens = preg_split( '/[_\-]|(?<=[a-z])(?=[A-Z])/', $key );
		if ( false === $tokens ) {
			return false;
		}
		foreach ( $tokens as $token ) {
			if ( 'email' === strtolower( $token ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Walk a subtree without redacting, but still account against the
	 * MAX_DEPTH / MAX_NODES limits so a malformed payload can't bypass the
	 * resource caps via a schema-metadata key.
	 *
	 * @throws RedactionLimitExceeded
	 */
	private function count_subtree_safe( $value, int $depth ): void {
		if ( $depth > self::MAX_DEPTH ) {
			throw new RedactionLimitExceeded( 'max_depth_exceeded' );
		}
		if ( is_array( $value ) ) {
			foreach ( $value as $v ) {
				if ( ++$this->node_count > self::MAX_NODES ) {
					throw new RedactionLimitExceeded( 'max_nodes_exceeded' );
				}
				$this->count_subtree_safe( $v, $depth + 1 );
			}
			return;
		}
		if ( is_object( $value ) ) {
			$this->count_subtree_safe( (array) $value, $depth + 1 );
		}
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
