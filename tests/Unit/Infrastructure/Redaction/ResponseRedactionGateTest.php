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
}
