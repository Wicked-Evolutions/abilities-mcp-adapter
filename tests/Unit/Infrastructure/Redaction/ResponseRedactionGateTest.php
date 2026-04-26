<?php
/**
 * Tests for ResponseRedactionGate — focused on Launch Gate bug C.4.
 *
 * The gate must apply per-ability Bucket 3 exemptions whether the ability
 * is invoked directly via `tools/call` or wrapped through the
 * `mcp-adapter/execute-ability` meta-tool. Bucket 1 (secrets) must always
 * apply regardless of exemption.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Infrastructure\Redaction;

use WickedEvolutions\McpAdapter\Infrastructure\Redaction\ResponseRedactionGate;
use WickedEvolutions\McpAdapter\Settings\SafetySettingsRepository as Repo;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class ResponseRedactionGateTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		$GLOBALS['wp_test_options']   = array();
		$GLOBALS['wp_test_abilities'] = array();
		ResponseRedactionGate::reset_name_cache_for_testing();
	}

	/**
	 * Register a fake ability so wp_get_abilities() returns it. Mirrors what
	 * the real plugin does at `wp_abilities_api_init` time — gives the
	 * gate's tool-name → ability-name translator a registry to consult.
	 */
	private function register_ability( string $slash_name ): void {
		$GLOBALS['wp_test_abilities'][ $slash_name ] = new \WP_Ability( $slash_name );
		ResponseRedactionGate::reset_name_cache_for_testing();
	}

	private function customer_response(): array {
		// Shape that ExecuteAbilityAbility wraps the underlying ability's data
		// in: {success: true, data: <ability response>}.
		return array(
			'success' => true,
			'data'    => array(
				'customers' => array(
					array(
						'id'            => 5,
						'email'         => 'jacob@willow.se',
						'first_name'    => 'Jacob',
						'session_token' => 'st_live_secret',
					),
				),
			),
		);
	}

	// ── Direct tools/call against a registered tool ────────────────────────

	public function test_direct_tools_call_redacts_when_no_exemption(): void {
		$out = ResponseRedactionGate::apply(
			$this->customer_response(),
			'tools/call',
			array( 'name' => 'fluent-cart/list-customers', 'arguments' => array() ),
			1
		);

		$this->assertSame( '[redacted:bucket_3]', $out['data']['customers'][0]['email'] );
		$this->assertSame( '[redacted:bucket_1]', $out['data']['customers'][0]['session_token'] );
	}

	public function test_direct_tools_call_skips_bucket3_when_ability_exempt(): void {
		Repo::add_exemption( Repo::BUCKET_CONTACT, 'fluent-cart/list-customers' );

		$out = ResponseRedactionGate::apply(
			$this->customer_response(),
			'tools/call',
			array( 'name' => 'fluent-cart/list-customers', 'arguments' => array() ),
			1
		);

		$this->assertSame( 'jacob@willow.se', $out['data']['customers'][0]['email'], 'Bucket 3 exemption should pass email through.' );
		$this->assertSame( '[redacted:bucket_1]', $out['data']['customers'][0]['session_token'], 'Bucket 1 must always redact regardless of exemption.' );
	}

	// ── Wrapped through mcp-adapter/execute-ability (the real AI path) ──────

	public function test_execute_ability_wrapper_redacts_when_no_exemption(): void {
		$out = ResponseRedactionGate::apply(
			$this->customer_response(),
			'tools/call',
			array(
				'name'      => 'mcp-adapter/execute-ability',
				'arguments' => array(
					'ability_name' => 'fluent-cart/list-customers',
					'parameters'   => array(),
				),
			),
			1
		);

		$this->assertSame( '[redacted:bucket_3]', $out['data']['customers'][0]['email'] );
		$this->assertSame( '[redacted:bucket_1]', $out['data']['customers'][0]['session_token'] );
	}

	public function test_execute_ability_wrapper_honours_inner_ability_exemption(): void {
		// THIS is bug C.4: exemption on the inner ability was being ignored
		// because the gate looked up the wrapper's name instead.
		Repo::add_exemption( Repo::BUCKET_CONTACT, 'fluent-cart/list-customers' );

		$out = ResponseRedactionGate::apply(
			$this->customer_response(),
			'tools/call',
			array(
				'name'      => 'mcp-adapter/execute-ability',
				'arguments' => array(
					'ability_name' => 'fluent-cart/list-customers',
					'parameters'   => array(),
				),
			),
			1
		);

		$this->assertSame( 'jacob@willow.se', $out['data']['customers'][0]['email'], 'Bucket 3 exemption on the inner ability must pass email through.' );
		$this->assertSame( '[redacted:bucket_1]', $out['data']['customers'][0]['session_token'], 'Bucket 1 must still redact even with Bucket 3 exempt.' );
	}

	public function test_execute_ability_wrapper_with_other_ability_does_not_borrow_exemption(): void {
		// Exempt fluent-cart/list-customers, but call users/list — should still redact.
		Repo::add_exemption( Repo::BUCKET_CONTACT, 'fluent-cart/list-customers' );

		$response = array(
			'success' => true,
			'data'    => array(
				'users' => array(
					array( 'id' => 1, 'email' => 'admin@example.com' ),
				),
			),
		);

		$out = ResponseRedactionGate::apply(
			$response,
			'tools/call',
			array(
				'name'      => 'mcp-adapter/execute-ability',
				'arguments' => array(
					'ability_name' => 'users/list',
					'parameters'   => array(),
				),
			),
			1
		);

		$this->assertSame( '[redacted:bucket_3]', $out['data']['users'][0]['email'] );
	}

	public function test_execute_ability_wrapper_missing_ability_name_redacts_normally(): void {
		// Defensive: malformed wrapper call without ability_name.
		// Falls back to "no ability scope" — full redaction applies.
		$out = ResponseRedactionGate::apply(
			$this->customer_response(),
			'tools/call',
			array(
				'name'      => 'mcp-adapter/execute-ability',
				'arguments' => array(),
			),
			1
		);

		$this->assertSame( '[redacted:bucket_3]', $out['data']['customers'][0]['email'] );
	}

	// ── batch-execute ───────────────────────────────────────────────────────

	public function test_batch_execute_does_not_apply_per_ability_exemptions(): void {
		// Documented limitation: a single redaction pass over a multi-ability
		// batch response cannot honour per-ability exemptions. Exempt
		// abilities lose their exemption inside batch — full redaction wins.
		Repo::add_exemption( Repo::BUCKET_CONTACT, 'fluent-cart/list-customers' );

		$batch_response = array(
			'results' => array(
				array(
					'content'           => array( array( 'type' => 'text', 'text' => '...' ) ),
					'structuredContent' => array( 'email' => 'jacob@willow.se' ),
				),
			),
		);

		$out = ResponseRedactionGate::apply(
			$batch_response,
			'tools/call',
			array(
				'name'      => 'mcp-adapter/batch-execute',
				'arguments' => array(
					'requests' => array(
						array( 'name' => 'fluent-cart/list-customers', 'arguments' => array() ),
					),
				),
			),
			1
		);

		$this->assertSame( '[redacted:bucket_3]', $out['results'][0]['structuredContent']['email'] );
	}

	// ── Exempt-then-unexempt round-trip ─────────────────────────────────────

	public function test_unexempting_clears_correctly(): void {
		Repo::add_exemption( Repo::BUCKET_CONTACT, 'fluent-cart/list-customers' );
		Repo::remove_exemption( Repo::BUCKET_CONTACT, 'fluent-cart/list-customers' );

		$out = ResponseRedactionGate::apply(
			$this->customer_response(),
			'tools/call',
			array(
				'name'      => 'mcp-adapter/execute-ability',
				'arguments' => array(
					'ability_name' => 'fluent-cart/list-customers',
					'parameters'   => array(),
				),
			),
			1
		);

		$this->assertSame( '[redacted:bucket_3]', $out['data']['customers'][0]['email'], 'After unexempt, email should redact again.' );
	}

	// ── Cross-bucket safety: exempting Bucket 3 must not exempt Bucket 1 ───

	public function test_bucket3_exemption_does_not_affect_bucket1_redaction(): void {
		// The repository deliberately exposes no API for Bucket 1 exemption.
		// But the redactor's defensive logic must hardcode Bucket 1 as
		// always-on, even if the exemption list somehow contained the ability.
		Repo::add_exemption( Repo::BUCKET_CONTACT, 'fluent-cart/list-customers' );

		$response = array(
			'success' => true,
			'data'    => array(
				'email'         => 'jacob@willow.se',
				'session_token' => 'st_live_secret',
				'api_key'       => 'sk_live_xxx',
				'password'      => 'hunter2',
			),
		);

		$out = ResponseRedactionGate::apply(
			$response,
			'tools/call',
			array(
				'name'      => 'mcp-adapter/execute-ability',
				'arguments' => array(
					'ability_name' => 'fluent-cart/list-customers',
					'parameters'   => array(),
				),
			),
			1
		);

		$this->assertSame( 'jacob@willow.se', $out['data']['email'], 'Bucket 3 exempt — email passes.' );
		$this->assertSame( '[redacted:bucket_1]', $out['data']['session_token'] );
		$this->assertSame( '[redacted:bucket_1]', $out['data']['api_key'] );
		$this->assertSame( '[redacted:bucket_1]', $out['data']['password'] );
	}

	// ── Non-tools/call methods don't extract ability names ──────────────────

	public function test_non_tools_call_methods_have_no_ability_scope(): void {
		// initialize / ping / etc. carry no ability — gate falls back to
		// "no scope" which means no exemption applies. The body wouldn't
		// normally contain PII at this method anyway, but a sentinel
		// e-mail in the body must redact.
		$response = array( 'data' => array( 'email' => 'jacob@willow.se' ) );

		$out = ResponseRedactionGate::apply(
			$response,
			'initialize',
			array(),
			1
		);

		$this->assertSame( '[redacted:bucket_3]', $out['data']['email'] );
	}

	// ── Pass-through for protocol error envelopes ───────────────────────────

	public function test_protocol_error_envelope_is_not_redacted(): void {
		$err = array(
			'error' => array(
				'code'    => -32600,
				'message' => 'Invalid Request',
			),
		);

		$out = ResponseRedactionGate::apply( $err, 'tools/call', array( 'name' => 'whatever' ), 1 );

		$this->assertSame( $err, $out );
	}

	// ── C.4 round 2: dash-form names from the MCP wire ─────────────────────
	//
	// MCP tool names cannot contain `/`; RegisterAbilityAsMcpTool advertises
	// abilities with dashes. params['name'] therefore arrives as the dash
	// form on every real call. The gate must translate dash → slash before
	// looking up exemptions (which are stored in slash form).

	public function test_round2_dash_form_meta_tool_unwraps_inner_ability(): void {
		// Register the inner ability so the dash→slash translator finds it.
		$this->register_ability( 'fluent-cart/list-customers' );
		Repo::add_exemption( Repo::BUCKET_CONTACT, 'fluent-cart/list-customers' );

		$out = ResponseRedactionGate::apply(
			$this->customer_response(),
			'tools/call',
			array(
				// Dash form — what real MCP clients send.
				'name'      => 'mcp-adapter-execute-ability',
				'arguments' => array(
					'ability_name' => 'fluent-cart/list-customers',
					'parameters'   => array(),
				),
			),
			1
		);

		$this->assertSame(
			'jacob@willow.se',
			$out['data']['customers'][0]['email'],
			'Dash-form meta-tool wrapper must still honour inner exemption.'
		);
		$this->assertSame( '[redacted:bucket_1]', $out['data']['customers'][0]['session_token'] );
	}

	public function test_round2_dash_form_batch_execute_returns_null_scope(): void {
		Repo::add_exemption( Repo::BUCKET_CONTACT, 'fluent-cart/list-customers' );

		$batch_response = array(
			'results' => array(
				array(
					'content'           => array( array( 'type' => 'text', 'text' => '...' ) ),
					'structuredContent' => array( 'email' => 'jacob@willow.se' ),
				),
			),
		);

		$out = ResponseRedactionGate::apply(
			$batch_response,
			'tools/call',
			array(
				'name'      => 'mcp-adapter-batch-execute',
				'arguments' => array(
					'requests' => array(
						array( 'name' => 'fluent-cart-list-customers', 'arguments' => array() ),
					),
				),
			),
			1
		);

		// Same documented limitation as the slash-form case: full redaction wins inside batch.
		$this->assertSame( '[redacted:bucket_3]', $out['results'][0]['structuredContent']['email'] );
	}

	public function test_round2_direct_call_dash_form_translates_to_slash_for_exemption(): void {
		// Real wire: a user calls fluent-cart/list-customers directly via tools/call.
		// MCP advertises the tool as `fluent-cart-list-customers` (dash form).
		// Exemption is stored in slash form. Dash→slash translation must succeed.
		$this->register_ability( 'fluent-cart/list-customers' );
		Repo::add_exemption( Repo::BUCKET_CONTACT, 'fluent-cart/list-customers' );

		$out = ResponseRedactionGate::apply(
			$this->customer_response(),
			'tools/call',
			array( 'name' => 'fluent-cart-list-customers', 'arguments' => array() ),
			1
		);

		$this->assertSame(
			'jacob@willow.se',
			$out['data']['customers'][0]['email'],
			'Direct dash-form tools/call must translate to slash for exemption lookup.'
		);
	}

	public function test_round2_unregistered_dash_name_falls_back_safely(): void {
		// No ability registered, so the translator can't find a slash form.
		// Falls back to the dash input. is_ability_exempt() with the dash
		// form returns false (exemptions are stored in slash form), so
		// redaction proceeds — safe default.
		$out = ResponseRedactionGate::apply(
			$this->customer_response(),
			'tools/call',
			array( 'name' => 'unknown-dash-name', 'arguments' => array() ),
			1
		);

		$this->assertSame( '[redacted:bucket_3]', $out['data']['customers'][0]['email'] );
	}

	public function test_round2_translator_returns_slash_input_unchanged(): void {
		// Defensive: if a caller (operator, batch-execute inner request,
		// future code path) somehow passes slash form through, leave it alone.
		$this->register_ability( 'fluent-cart/list-customers' );

		$this->assertSame(
			'fluent-cart/list-customers',
			ResponseRedactionGate::tool_name_to_ability_name( 'fluent-cart/list-customers' )
		);
	}

	public function test_round2_translator_maps_dash_to_slash_when_registered(): void {
		$this->register_ability( 'fluent-cart/list-customers' );
		$this->register_ability( 'users/list' );

		$this->assertSame(
			'fluent-cart/list-customers',
			ResponseRedactionGate::tool_name_to_ability_name( 'fluent-cart-list-customers' )
		);
		$this->assertSame(
			'users/list',
			ResponseRedactionGate::tool_name_to_ability_name( 'users-list' )
		);
	}

	public function test_round2_translator_returns_input_when_unregistered(): void {
		$this->assertSame(
			'no-such-ability',
			ResponseRedactionGate::tool_name_to_ability_name( 'no-such-ability' )
		);
	}

	public function test_round2_translator_handles_nested_namespaces(): void {
		// Multi-segment slash names — every `/` becomes `-`. The dash form
		// `wp-mcp-adapter-discover-abilities` is ambiguous in principle (could
		// map to `wp/mcp-adapter/discover-abilities` or other splits), but
		// the registry lookup resolves to the actual registered slash form.
		$this->register_ability( 'wp/mcp-adapter/discover-abilities' );

		$this->assertSame(
			'wp/mcp-adapter/discover-abilities',
			ResponseRedactionGate::tool_name_to_ability_name( 'wp-mcp-adapter-discover-abilities' )
		);
	}

	public function test_round2_translator_first_write_wins_on_dash_collision(): void {
		// `a/b-c` and `a-b/c` both produce dash form `a-b-c`. The first
		// registered ability wins; the second collision is ignored. This
		// is a naming convention the platform inherits from the MCP spec
		// (tool names can't contain `/`); ability authors must avoid
		// dash collisions.
		$this->register_ability( 'a/b-c' );
		// Register the colliding one — should NOT overwrite the first.
		$GLOBALS['wp_test_abilities']['a-b/c'] = new \WP_Ability( 'a-b/c' );
		ResponseRedactionGate::reset_name_cache_for_testing();

		$this->assertSame( 'a/b-c', ResponseRedactionGate::tool_name_to_ability_name( 'a-b-c' ) );
	}

	public function test_round2_dash_form_cross_bucket_safety_preserved(): void {
		// Repeat of the bucket-1-immunity test, this time over the dash-form
		// wire path that was broken in round 1.
		$this->register_ability( 'fluent-cart/list-customers' );
		Repo::add_exemption( Repo::BUCKET_CONTACT, 'fluent-cart/list-customers' );

		$response = array(
			'success' => true,
			'data'    => array(
				'email'         => 'jacob@willow.se',
				'session_token' => 'st_live_secret',
				'api_key'       => 'sk_live_xxx',
			),
		);

		$out = ResponseRedactionGate::apply(
			$response,
			'tools/call',
			array(
				'name'      => 'mcp-adapter-execute-ability',
				'arguments' => array(
					'ability_name' => 'fluent-cart/list-customers',
					'parameters'   => array(),
				),
			),
			1
		);

		$this->assertSame( 'jacob@willow.se', $out['data']['email'] );
		$this->assertSame( '[redacted:bucket_1]', $out['data']['session_token'] );
		$this->assertSame( '[redacted:bucket_1]', $out['data']['api_key'] );
	}

	// ── Text-channel leak fix (Launch Gate v0.1.1) ──────────────────────────
	//
	// `tools/call` ships responses on two parallel channels: the typed
	// `structuredContent` tree, and a JSON-encoded snapshot at
	// `content[i].text`. The gate's recursive redactor mutates the typed
	// tree but keyword-based redaction can't match anything in a serialised
	// string, so the text channel previously leaked raw values even when
	// the typed channel was correctly redacted.

	/**
	 * Build the response shape ToolsHandler::call_tool() emits for a non-image
	 * ability — content[0].text is wp_json_encode($result) and structuredContent
	 * is the same $result, captured BEFORE the gate runs.
	 *
	 * @param array $result_payload What the ability returned.
	 * @return array
	 */
	private function tools_call_response( array $result_payload ): array {
		return array(
			'content'           => array(
				array(
					'type' => 'text',
					'text' => json_encode( $result_payload ),
				),
			),
			'structuredContent' => $result_payload,
		);
	}

	public function test_text_channel_dual_channel_text_regenerates_from_redacted_structured(): void {
		$payload = array(
			'users' => array(
				array(
					'id'            => 5,
					'email'         => 'jacob@willow.se',
					'session_token' => 'st_live_secret',
				),
			),
		);

		$out = ResponseRedactionGate::apply(
			$this->tools_call_response( $payload ),
			'tools/call',
			array( 'name' => 'users-list', 'arguments' => array() ),
			1
		);

		// structuredContent redacted as before.
		$this->assertSame( '[redacted:bucket_3]', $out['structuredContent']['users'][0]['email'] );
		$this->assertSame( '[redacted:bucket_1]', $out['structuredContent']['users'][0]['session_token'] );

		// content[0].text must be regenerated from the redacted structuredContent —
		// no raw email or secret may remain in the serialised string.
		$text = $out['content'][0]['text'];
		$this->assertIsString( $text );
		$this->assertStringNotContainsString( 'jacob@willow.se', $text );
		$this->assertStringNotContainsString( 'st_live_secret', $text );
		$this->assertStringContainsString( '[redacted:bucket_3]', $text );
		$this->assertStringContainsString( '[redacted:bucket_1]', $text );

		// And the regenerated text must round-trip back to the redacted tree.
		$decoded = json_decode( $text, true );
		$this->assertSame( $out['structuredContent'], $decoded );
	}

	public function test_text_channel_via_execute_ability_meta_tool_dash_form(): void {
		// The end-to-end scenario GPT 5.5 hit: AI calls fluent-cart/list-customers
		// through mcp-adapter-execute-ability. Inner result wraps in
		// {success, data:...}; ToolsHandler builds dual-channel; gate must
		// redact both channels.
		$this->register_ability( 'fluent-cart/list-customers' );

		$inner_payload = array(
			'success' => true,
			'data'    => array(
				'customers' => array(
					array( 'id' => 5, 'email' => 'jacob@willow.se' ),
				),
			),
		);

		$out = ResponseRedactionGate::apply(
			$this->tools_call_response( $inner_payload ),
			'tools/call',
			array(
				'name'      => 'mcp-adapter-execute-ability',
				'arguments' => array(
					'ability_name' => 'fluent-cart/list-customers',
					'parameters'   => array(),
				),
			),
			1
		);

		$this->assertSame( '[redacted:bucket_3]', $out['structuredContent']['data']['customers'][0]['email'] );
		$this->assertStringNotContainsString( 'jacob@willow.se', $out['content'][0]['text'] );
	}

	public function test_text_channel_exemption_passes_email_through_both_channels(): void {
		// When an ability is exempt, BOTH channels must show the unredacted value —
		// otherwise the user sees inconsistent data depending on which channel
		// the client surfaces.
		$this->register_ability( 'fluent-cart/list-customers' );
		Repo::add_exemption( Repo::BUCKET_CONTACT, 'fluent-cart/list-customers' );

		$payload = array(
			'data' => array( 'email' => 'jacob@willow.se', 'session_token' => 'st_live_secret' ),
		);

		$out = ResponseRedactionGate::apply(
			$this->tools_call_response( $payload ),
			'tools/call',
			array(
				'name'      => 'mcp-adapter-execute-ability',
				'arguments' => array(
					'ability_name' => 'fluent-cart/list-customers',
					'parameters'   => array(),
				),
			),
			1
		);

		// Bucket 3 exempt — email passes on both channels.
		$this->assertSame( 'jacob@willow.se', $out['structuredContent']['data']['email'] );
		$this->assertStringContainsString( 'jacob@willow.se', $out['content'][0]['text'] );
		// Bucket 1 still redacts on both.
		$this->assertSame( '[redacted:bucket_1]', $out['structuredContent']['data']['session_token'] );
		$this->assertStringNotContainsString( 'st_live_secret', $out['content'][0]['text'] );
	}

	public function test_text_channel_image_response_untouched(): void {
		// ToolsHandler emits image responses without structuredContent and
		// without content[0].text. The reconciler must not invent a text
		// field or otherwise mutate the image path.
		$image_response = array(
			'content' => array(
				array(
					'type'     => 'image',
					'data'     => 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII=',
					'mimeType' => 'image/png',
				),
			),
		);

		$out = ResponseRedactionGate::apply(
			$image_response,
			'tools/call',
			array( 'name' => 'screenshot/capture', 'arguments' => array() ),
			1
		);

		$this->assertSame( 'image', $out['content'][0]['type'] );
		$this->assertSame( $image_response['content'][0]['data'], $out['content'][0]['data'] );
		$this->assertSame( 'image/png', $out['content'][0]['mimeType'] );
		$this->assertArrayNotHasKey( 'text', $out['content'][0] );
		$this->assertArrayNotHasKey( 'structuredContent', $out );
	}

	public function test_text_channel_text_only_response_decoded_redacted_re_encoded(): void {
		// Single-channel text response (no structuredContent). The reconciler
		// best-effort decodes the JSON, runs redaction, re-encodes. PII must
		// not leak in the text.
		$payload = array( 'email' => 'jacob@willow.se', 'name' => 'Jacob' );

		$response = array(
			'content' => array(
				array(
					'type' => 'text',
					'text' => json_encode( $payload ),
				),
			),
		);

		$out = ResponseRedactionGate::apply(
			$response,
			'tools/call',
			array( 'name' => 'users-list', 'arguments' => array() ),
			1
		);

		$text = $out['content'][0]['text'];
		$this->assertStringNotContainsString( 'jacob@willow.se', $text );
		$this->assertStringContainsString( '[redacted:bucket_3]', $text );
		// Non-PII fields preserved.
		$this->assertStringContainsString( 'Jacob', $text );
	}

	public function test_text_channel_plain_string_text_left_alone(): void {
		// content[0].text that is a plain non-JSON string has no field-name
		// surface for keyword redaction. Reconciler must leave it intact —
		// rewriting plain text would be a behaviour change the brief forbids.
		$response = array(
			'content' => array(
				array(
					'type' => 'text',
					'text' => 'Hello world. No PII here.',
				),
			),
		);

		$out = ResponseRedactionGate::apply(
			$response,
			'tools/call',
			array( 'name' => 'docs/get', 'arguments' => array() ),
			1
		);

		$this->assertSame( 'Hello world. No PII here.', $out['content'][0]['text'] );
	}

	public function test_text_channel_multiple_text_parts_all_regenerate(): void {
		// Defensive: the adapter writes only content[0] today, but the
		// reconciler must regenerate every text part if a future handler
		// emits several from the same structured payload.
		$payload  = array( 'email' => 'jacob@willow.se' );
		$response = array(
			'content'           => array(
				array( 'type' => 'text', 'text' => json_encode( $payload ) ),
				array( 'type' => 'text', 'text' => json_encode( $payload ) ),
			),
			'structuredContent' => $payload,
		);

		$out = ResponseRedactionGate::apply(
			$response,
			'tools/call',
			array( 'name' => 'users-list', 'arguments' => array() ),
			1
		);

		$this->assertStringNotContainsString( 'jacob@willow.se', $out['content'][0]['text'] );
		$this->assertStringNotContainsString( 'jacob@willow.se', $out['content'][1]['text'] );
		$this->assertSame( $out['content'][0]['text'], $out['content'][1]['text'] );
	}

	public function test_text_channel_non_tools_call_unchanged(): void {
		// `initialize` and other non-tool methods don't have content/structuredContent.
		// The reconciler must be a no-op for them.
		$response = array(
			'protocolVersion' => '2025-06-18',
			'capabilities'    => array( 'tools' => array() ),
		);

		$out = ResponseRedactionGate::apply( $response, 'initialize', array(), 1 );

		$this->assertSame( $response, $out );
	}

	public function test_text_channel_response_without_content_unchanged(): void {
		// Defensive: tools/call result without a `content` key (theoretical /
		// future shape) passes through unchanged.
		$response = array( 'data' => array( 'email' => 'jacob@willow.se' ) );

		$out = ResponseRedactionGate::apply(
			$response,
			'tools/call',
			array( 'name' => 'whatever', 'arguments' => array() ),
			1
		);

		// structuredContent path doesn't apply, but the typed tree is still
		// redacted by the main pass.
		$this->assertSame( '[redacted:bucket_3]', $out['data']['email'] );
		$this->assertArrayNotHasKey( 'content', $out );
	}

	public function test_text_channel_metadata_preserved_through_reconciliation(): void {
		// Internal _metadata bookkeeping must survive the reconciler — it's
		// extracted in apply() before redaction and re-attached after.
		$payload = array( 'email' => 'jacob@willow.se' );
		$response = array(
			'content'           => array(
				array( 'type' => 'text', 'text' => json_encode( $payload ) ),
			),
			'structuredContent' => $payload,
			'_metadata'         => array( 'component_type' => 'tool', 'tool_name' => 'users/list' ),
		);

		$out = ResponseRedactionGate::apply(
			$response,
			'tools/call',
			array( 'name' => 'users-list', 'arguments' => array() ),
			1
		);

		$this->assertSame( array( 'component_type' => 'tool', 'tool_name' => 'users/list' ), $out['_metadata'] );
		$this->assertStringNotContainsString( 'jacob@willow.se', $out['content'][0]['text'] );
	}
}
