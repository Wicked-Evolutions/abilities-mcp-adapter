<?php
/**
 * Regression coverage for issue #113 — `tools/list` and `tools/list/all`
 * JSON-RPC responses must NOT have their per-tool `inputSchema` /
 * `outputSchema` subtrees corrupted by the redaction pipeline.
 *
 * Completes the schema-metadata exemption pattern shipped by issue #105
 * for the per-ability meta-tool path. The same defect surfaces on the
 * method-level path: `tools/list` carries the same JSON Schema objects as
 * `mcp-adapter/get-ability-info` but under MCP wire keys (`inputSchema`,
 * `outputSchema`, camelCase) and with no per-ability name to key the
 * existing #105 exemption against.
 *
 * Source: live capture from helenawillow.com 2026-05-10 — 40 of 789 tools
 * had property schemas replaced by `["[redacted:bucket_3]"]`, breaking
 * Anthropic API draft 2020-12 validation and yielding zero loaded tools.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Infrastructure\Redaction;

use WickedEvolutions\McpAdapter\Infrastructure\Redaction\RedactionLimitExceeded;
use WickedEvolutions\McpAdapter\Infrastructure\Redaction\ResponseRedactionGate;
use WickedEvolutions\McpAdapter\Infrastructure\Redaction\ResponseRedactor;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class ToolsListSchemaExemptionTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		$GLOBALS['wp_test_options']   = array();
		$GLOBALS['wp_test_abilities'] = array();
		ResponseRedactionGate::reset_name_cache_for_testing();
	}

	/**
	 * Build a `tools/list` response shape (mirrors
	 * {@see \WickedEvolutions\McpAdapter\Handlers\Tools\ToolsHandler::list_tools()}).
	 * One entry per `$tools` row — each row is `[ name, inputSchemaProps,
	 * outputSchemaProps ]`. `_metadata` is stripped by the gate before
	 * redaction; we mirror that strip so direct-redactor tests see the same
	 * shape as the gate-fed redactor.
	 *
	 * @param array<int,array{0:string,1:array<string,mixed>,2:array<string,mixed>}> $tools
	 */
	private function tools_list_response( array $tools ): array {
		$entries = array();
		foreach ( $tools as $row ) {
			[ $name, $input_props, $output_props ] = $row;
			$entries[] = array(
				'name'         => $name,
				'description'  => 'desc for ' . $name,
				'type'         => 'action',
				'inputSchema'  => array(
					'type'                 => 'object',
					'properties'           => $input_props,
					'required'             => array_keys( $input_props ),
					'additionalProperties' => false,
				),
				'outputSchema' => array(
					'type'       => 'object',
					'properties' => $output_props,
				),
			);
		}

		return array( 'tools' => $entries );
	}

	// ── Pin the live-captured bug shape (the array-sentinel replacement) ───

	public function test_tools_list_pii_keyed_property_schema_passes_through(): void {
		// Live capture shape: presto-player-create-email-collection had its
		// `email_provider` property schema replaced by `["[redacted:bucket_3]"]`.
		$response = $this->tools_list_response(
			array(
				array(
					'presto-player-create-email-collection',
					array(
						'enabled'        => array( 'type' => 'boolean' ),
						'email_provider' => array( 'type' => 'string', 'description' => 'Provider key' ),
					),
					array(
						'id' => array( 'type' => 'integer' ),
					),
				),
			)
		);

		$out = ResponseRedactionGate::apply( $response, 'tools/list', array(), 1 );

		$this->assertSame(
			array( 'type' => 'string', 'description' => 'Provider key' ),
			$out['tools'][0]['inputSchema']['properties']['email_provider'],
			'#113: inputSchema property whose name matches Bucket 3 must pass through verbatim on tools/list.'
		);
		$this->assertNotSame(
			array( '[redacted:bucket_3]' ),
			$out['tools'][0]['inputSchema']['properties']['email_provider'],
			'#113: the array-sentinel marker must NOT appear inside a tools/list schema.'
		);
	}

	public function test_tools_list_input_and_output_schema_pass_through_for_all_known_pii_property_families(): void {
		// Covers the 40-tool failure surface from #113 — email family,
		// password, address, ip — across both schemas on a single tool.
		$response = $this->tools_list_response(
			array(
				array(
					'users-create',
					array(
						'username' => array( 'type' => 'string', 'description' => 'WordPress login' ),
						'email'    => array( 'type' => 'string', 'format' => 'email' ),
						'password' => array( 'type' => 'string', 'minLength' => 8 ),
						'phone'    => array( 'type' => 'string' ),
					),
					array(
						'id'             => array( 'type' => 'integer' ),
						'email'          => array( 'type' => 'string', 'format' => 'email' ),
						'admin_email'    => array( 'type' => 'string', 'format' => 'email' ),
						'address_line_1' => array( 'type' => 'string' ),
						'ip'             => array( 'type' => 'string' ),
					),
				),
			)
		);

		$out = ResponseRedactionGate::apply( $response, 'tools/list', array(), 1 );

		$input_props  = $out['tools'][0]['inputSchema']['properties'];
		$output_props = $out['tools'][0]['outputSchema']['properties'];

		$this->assertSame( array( 'type' => 'string', 'description' => 'WordPress login' ), $input_props['username'] );
		$this->assertSame( array( 'type' => 'string', 'format' => 'email' ),                $input_props['email'] );
		$this->assertSame( array( 'type' => 'string', 'minLength' => 8 ),                   $input_props['password'] );
		$this->assertSame( array( 'type' => 'string' ),                                      $input_props['phone'] );

		$this->assertSame( array( 'type' => 'integer' ),                $output_props['id'] );
		$this->assertSame( array( 'type' => 'string', 'format' => 'email' ), $output_props['email'] );
		$this->assertSame( array( 'type' => 'string', 'format' => 'email' ), $output_props['admin_email'] );
		$this->assertSame( array( 'type' => 'string' ),                  $output_props['address_line_1'] );
		$this->assertSame( array( 'type' => 'string' ),                  $output_props['ip'] );
	}

	public function test_tools_list_all_variant_also_passes_schemas_through(): void {
		// `tools/list/all` shape mirrors `tools/list` (per
		// ToolsHandler::list_all_tools()) with an extra `available` bool.
		// Both methods route through the same redaction gate.
		$response = $this->tools_list_response(
			array(
				array(
					'fluent-crm-create-contact',
					array(
						'email'          => array( 'type' => 'string', 'format' => 'email' ),
						'phone'          => array( 'type' => 'string' ),
						'address_line_1' => array( 'type' => 'string' ),
					),
					array(
						'id'    => array( 'type' => 'integer' ),
						'email' => array( 'type' => 'string', 'format' => 'email' ),
					),
				),
			)
		);
		$response['tools'][0]['available'] = true;

		$out = ResponseRedactionGate::apply( $response, 'tools/list/all', array(), 1 );

		$this->assertSame(
			array( 'type' => 'string', 'format' => 'email' ),
			$out['tools'][0]['inputSchema']['properties']['email']
		);
		$this->assertSame(
			array( 'type' => 'string', 'format' => 'email' ),
			$out['tools'][0]['outputSchema']['properties']['email']
		);
		$this->assertTrue( $out['tools'][0]['available'] );
	}

	public function test_tools_list_clean_payload_remains_clean(): void {
		// No-false-positive case: a tool whose schemas contain no
		// PII-keyword-matching property names must survive the redaction
		// pass unchanged. Pin the full schema by equality so any silent
		// mutation regresses the test.
		$response = $this->tools_list_response(
			array(
				array(
					'posts-list',
					array(
						'per_page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100 ),
						'status'   => array( 'type' => 'string', 'default' => 'publish' ),
					),
					array(
						'posts' => array( 'type' => 'array' ),
					),
				),
			)
		);

		$out = ResponseRedactionGate::apply( $response, 'tools/list', array(), 1 );

		$this->assertSame( $response['tools'][0]['inputSchema'],  $out['tools'][0]['inputSchema'] );
		$this->assertSame( $response['tools'][0]['outputSchema'], $out['tools'][0]['outputSchema'] );
	}

	public function test_tools_list_redaction_counts_stay_zero_on_schema_payload(): void {
		// Counter pin: traversing the exempt schema subtree must NOT
		// increment any bucket counter. Mirrors
		// SchemaPathExemptionTest::test_schema_subtree_does_not_increment_redaction_counters
		// for the method-level path.
		$response = $this->tools_list_response(
			array(
				array(
					'users-create',
					array(
						'username' => array( 'type' => 'string' ),
						'email'    => array( 'type' => 'string', 'format' => 'email' ),
						'password' => array( 'type' => 'string' ),
					),
					array(
						'id' => array( 'type' => 'integer' ),
					),
				),
			)
		);

		$redactor = new ResponseRedactor( null, 'tools/list' );
		$redactor->redact( $response );
		$counts = $redactor->get_counts();

		$this->assertSame( 0, $counts[1], 'Schema subtree must not increment Bucket 1 counter on tools/list.' );
		$this->assertSame( 0, $counts[2] );
		$this->assertSame( 0, $counts[3], 'Schema subtree must not increment Bucket 3 counter on tools/list.' );
	}

	// ── Negative-control: runtime-value redaction on tools/call still fires ──

	public function test_negative_control_tools_call_users_list_still_redacts_email(): void {
		// Proves the exemption is method-scoped: a `tools/call` response
		// against a PII-returning ability still redacts the runtime values.
		// `users-list` is reachable on any WordPress site with at least one
		// user — the always-available negative-control target named in
		// the sprint plan acceptance gate.
		$tools_call_response = array(
			'content'           => array(
				array(
					'type' => 'text',
					'text' => '{"users":[{"id":1,"email":"jacob@willow.se"}]}',
				),
			),
			'structuredContent' => array(
				'users' => array(
					array(
						'id'    => 1,
						'email' => 'jacob@willow.se',
					),
				),
			),
		);

		$out = ResponseRedactionGate::apply(
			$tools_call_response,
			'tools/call',
			array( 'name' => 'users-list', 'arguments' => array() ),
			1
		);

		$this->assertSame( '[redacted:bucket_3]', $out['structuredContent']['users'][0]['email'] );
		$this->assertStringContainsString( '[redacted:bucket_3]', $out['content'][0]['text'], 'Dual-channel text snapshot must be regenerated from redacted structuredContent.' );
		$this->assertStringNotContainsString( 'jacob@willow.se', $out['content'][0]['text'] );
	}

	public function test_negative_control_other_method_does_not_inherit_exemption(): void {
		// `resources/list` or any other method outside SCHEMA_METADATA_METHODS
		// must NOT inherit the exemption — runtime PII in a hypothetical
		// resource listing would still redact. Pins the method allowlist as
		// an allowlist, not a blanket pass-through.
		$response = array(
			'resources' => array(
				array(
					'name'  => 'user-record',
					'email' => 'jacob@willow.se',
				),
			),
		);

		$out = ResponseRedactionGate::apply( $response, 'resources/list', array(), 1 );

		$this->assertSame( '[redacted:bucket_3]', $out['resources'][0]['email'] );
	}

	public function test_negative_control_runtime_payload_with_inputSchema_named_key_does_not_bypass(): void {
		// Smuggling defence: when the method is OUTSIDE the allowlist, a
		// runtime payload that happens to contain a key literally named
		// `inputSchema` must still redact downstream PII. Mirrors
		// SchemaPathExemptionTest::test_meta_list_post_meta_with_input_schema_named_meta_value_does_not_bypass_redaction
		// for the method-level path.
		$response = array(
			'meta' => array(
				'inputSchema' => array(
					'admin_email' => 'admin@example.com',
				),
			),
		);

		$out = ResponseRedactionGate::apply(
			$response,
			'tools/call',
			array( 'name' => 'meta-get-post-meta', 'arguments' => array() ),
			1
		);

		$this->assertSame( '[redacted:bucket_3]', $out['meta']['inputSchema']['admin_email'] );
	}

	// ── Direct redactor unit-level coverage ────────────────────────────────

	public function test_redactor_constructed_with_tools_list_method_activates_exemption(): void {
		$response = array(
			'tools' => array(
				array(
					'name'        => 'users-create',
					'inputSchema' => array(
						'properties' => array(
							'email' => array( 'type' => 'string', 'format' => 'email' ),
						),
					),
				),
			),
		);

		$out = ( new ResponseRedactor( null, 'tools/list' ) )->redact( $response );

		$this->assertSame(
			array( 'type' => 'string', 'format' => 'email' ),
			$out['tools'][0]['inputSchema']['properties']['email']
		);
	}

	public function test_redactor_constructed_with_unrelated_method_does_not_activate_exemption(): void {
		// Defensive: passing a non-allowlisted method must not bypass the
		// per-key field-name check. A key literally named `inputSchema`
		// at runtime still redacts PII underneath.
		$response = array(
			'inputSchema' => array(
				'admin_email' => 'admin@example.com',
			),
		);

		$out = ( new ResponseRedactor( null, 'initialize' ) )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['inputSchema']['admin_email'] );
	}

	public function test_redactor_with_null_method_preserves_pre_113_behaviour(): void {
		// Backward-compat pin: callers that don't pass a method (the
		// pre-#113 constructor signature) still see the redactor behave
		// exactly as before. Mirrors the existing
		// SchemaPathExemptionTest::test_no_ability_name_disables_schema_exemption
		// assertion shape.
		$response = array(
			'inputSchema' => array(
				'admin_email' => 'admin@example.com',
			),
		);

		$out = ( new ResponseRedactor( null ) )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['inputSchema']['admin_email'] );
	}

	// ── Limits still enforced through method-path exemption ───────────────

	public function test_max_nodes_guard_still_fires_on_oversized_tools_list_payload(): void {
		$big = array();
		for ( $i = 0; $i < ResponseRedactor::MAX_NODES + 10; $i++ ) {
			$big[ 'k' . $i ] = $i;
		}
		$response = array(
			'tools' => array(
				array(
					'inputSchema' => $big,
				),
			),
		);

		$this->expectException( RedactionLimitExceeded::class );
		( new ResponseRedactor( null, 'tools/list' ) )->redact( $response );
	}
}
