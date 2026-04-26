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
		$GLOBALS['wp_test_options'] = array();
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
}
