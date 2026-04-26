<?php

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Infrastructure\Redaction;

use WickedEvolutions\McpAdapter\Infrastructure\Redaction\RedactionConfig;
use WickedEvolutions\McpAdapter\Infrastructure\Redaction\RedactionLimitExceeded;
use WickedEvolutions\McpAdapter\Infrastructure\Redaction\ResponseRedactor;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class ResponseRedactorTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		$GLOBALS['wp_test_options'] = array();
	}

	// ── Behavioral acceptance ─────────────────────────────────────────────────

	public function test_users_list_default_redacts_email_and_user_login(): void {
		$response = array(
			'users' => array(
				array(
					'id'         => 5,
					'email'      => 'jacob@willow.se',
					'user_login' => 'jacob',
					'first_name' => 'Jacob',
					'last_name'  => 'Willow',
					'roles'      => array( 'administrator' ),
				),
			),
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['users'][0]['email'] );
		$this->assertSame( '[redacted:bucket_3]', $out['users'][0]['user_login'] );
		$this->assertSame( 'Jacob', $out['users'][0]['first_name'] );
		$this->assertSame( 'Willow', $out['users'][0]['last_name'] );
		$this->assertSame( 5, $out['users'][0]['id'] );
		$this->assertSame( array( 'administrator' ), $out['users'][0]['roles'] );
	}

	public function test_fluent_cart_list_customers_redacts_email_passes_lifetime_value(): void {
		$response = array(
			'customers' => array(
				array(
					'id'             => 12,
					'contact_id'     => 'c_99',
					'first_name'     => 'A',
					'last_name'      => 'B',
					'email'          => 'a@b.com',
					'lifetime_value' => 1234.56,
				),
			),
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['customers'][0]['email'] );
		$this->assertSame( 'A', $out['customers'][0]['first_name'] );
		$this->assertSame( 'B', $out['customers'][0]['last_name'] );
		$this->assertSame( 12, $out['customers'][0]['id'] );
		$this->assertSame( 'c_99', $out['customers'][0]['contact_id'] );
		$this->assertSame( 1234.56, $out['customers'][0]['lifetime_value'] );
	}

	public function test_user_meta_redacts_session_tokens_and_user_pass(): void {
		$response = array(
			'meta' => array(
				'session_tokens' => array( 'abcd1234', 'efgh5678' ),
				'user_pass'      => '$P$Bsomethinghashy',
				'last_login'     => '2026-04-26',
			),
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		// session_tokens is Bucket 1 by name → array shape preserved.
		$this->assertSame( array( '[redacted:bucket_1]' ), $out['meta']['session_tokens'] );
		// user_pass is Bucket 1 by name → scalar string marker.
		$this->assertSame( '[redacted:bucket_1]', $out['meta']['user_pass'] );
		$this->assertSame( '2026-04-26', $out['meta']['last_login'] );
	}

	public function test_master_toggle_off_keeps_bucket_1_active_and_passes_bucket_3(): void {
		update_option( RedactionConfig::OPTION_MASTER_ENABLED, false );

		$response = array(
			'email'    => 'a@b.com',          // Bucket 3 → passes through.
			'password' => 'hunter2',          // Bucket 1 → still redacted.
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame( 'a@b.com', $out['email'] );
		$this->assertSame( '[redacted:bucket_1]', $out['password'] );
	}

	public function test_per_ability_bucket3_exemption_unblocks_email_keeps_bucket2(): void {
		update_option(
			RedactionConfig::OPTION_BUCKET3_EXEMPTIONS,
			array( 'fluent-cart/list-customers' )
		);

		$response = array(
			'email'       => 'a@b.com',
			'card_number' => '4242424242424242', // Bucket 2 → still redacted.
		);

		$out = ( new ResponseRedactor( 'fluent-cart/list-customers' ) )->redact( $response );

		$this->assertSame( 'a@b.com', $out['email'] );
		$this->assertSame( '[redacted:bucket_2]', $out['card_number'] );
	}

	public function test_string_email_redacts_to_scalar_string_marker(): void {
		$out = ( new ResponseRedactor() )->redact( array( 'email' => 'a@b.com' ) );
		$this->assertIsString( $out['email'] );
		$this->assertSame( '[redacted:bucket_3]', $out['email'] );
	}

	public function test_object_address_redacts_to_object_marker(): void {
		$response = array(
			'address' => (object) array(
				'street' => '1 Foo St',
				'city'   => 'Bar',
			),
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertIsObject( $out['address'] );
		$this->assertTrue( $out['address']->redacted );
		$this->assertSame( 'bucket_3', $out['address']->reason );
	}

	public function test_array_of_phones_redacts_to_single_element_array(): void {
		$response = array(
			'phone' => array( '+46-700-000-000', '+46-700-000-001' ),
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame( array( '[redacted:bucket_3]' ), $out['phone'] );
	}

	public function test_custom_keyword_added_to_bucket3_list(): void {
		update_option(
			RedactionConfig::OPTION_BUCKET3_KEYWORDS,
			array( 'gravity_forms_secret' )
		);

		$out = ( new ResponseRedactor() )->redact(
			array( 'gravity_forms_secret' => 'something' )
		);

		$this->assertSame( '[redacted:bucket_3]', $out['gravity_forms_secret'] );
	}

	// ── Implementation acceptance ─────────────────────────────────────────────

	public function test_type_detection_handles_six_type_cases(): void {
		$response = array(
			'email_string' => 'a@b.com',
			'email_number' => 99,             // not a redaction target by name; included to verify pass-through
			'email'        => 1234,            // numeric value of a redacted field → null
			'flag'         => true,            // booleans untouched
			'address'      => (object) array( 'x' => 1 ),
			'phone'        => array( 'a', 'b' ),
			'unknown'      => null,
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame( 'a@b.com', $out['email_string'] );        // wrong key → pass.
		$this->assertSame( 99, $out['email_number'] );               // wrong key → pass.
		$this->assertNull( $out['email'] );                          // numeric of redacted → null.
		$this->assertTrue( $out['flag'] );
		$this->assertIsObject( $out['address'] );
		$this->assertSame( array( '[redacted:bucket_3]' ), $out['phone'] );
		$this->assertNull( $out['unknown'] );
	}

	public function test_recursive_traversal_through_nested_arrays(): void {
		$response = array(
			'level1' => array(
				'level2' => array(
					'level3' => array(
						'email' => 'deep@example.com',
						'name'  => 'OK',
					),
				),
			),
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['level1']['level2']['level3']['email'] );
		$this->assertSame( 'OK', $out['level1']['level2']['level3']['name'] );
	}

	public function test_max_nodes_guard_throws(): void {
		$big = array();
		for ( $i = 0; $i < ResponseRedactor::MAX_NODES + 10; $i++ ) {
			$big[ 'k' . $i ] = $i;
		}

		$this->expectException( RedactionLimitExceeded::class );
		( new ResponseRedactor() )->redact( $big );
	}

	public function test_max_depth_guard_throws(): void {
		// Build a deeply nested array beyond MAX_DEPTH.
		$leaf = array( 'leaf' => 1 );
		for ( $i = 0; $i < ResponseRedactor::MAX_DEPTH + 5; $i++ ) {
			$leaf = array( 'n' => $leaf );
		}

		$this->expectException( RedactionLimitExceeded::class );
		( new ResponseRedactor() )->redact( $leaf );
	}

	public function test_pattern_matcher_only_runs_on_scalar_strings(): void {
		// Mixed-type fixture; values that LOOK like card numbers but aren't strings should pass.
		$response = array(
			'note'        => 'normal text 4242424242424242 in body',  // SCALAR STRING — Luhn-pattern PAN as part of free text.
			'note_array'  => array( '4242424242424242' ),              // string-in-array — also a scalar string at depth 1.
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		// The string `4242424242424242` standalone should be redacted by Luhn.
		// But "normal text 4242424242424242 in body" is NOT a contiguous 13-19 digit string, so it passes.
		$this->assertSame( 'normal text 4242424242424242 in body', $out['note'] );
		// The array element IS a contiguous Luhn-passing PAN → redacted.
		$this->assertSame( array( '[redacted:bucket_2]' ), $out['note_array'] );
	}

	public function test_case_insensitive_field_match(): void {
		$response = array(
			'EMAIL' => 'a@b.com',
			'Email' => 'c@d.com',
			'email' => 'e@f.com',
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['EMAIL'] );
		$this->assertSame( '[redacted:bucket_3]', $out['Email'] );
		$this->assertSame( '[redacted:bucket_3]', $out['email'] );
	}

	public function test_no_regex_over_full_json_document(): void {
		$response = array(
			'note' => 'hi my email is jacob@willow.se thanks',
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame( 'hi my email is jacob@willow.se thanks', $out['note'] );
	}

	// ── Adversarial acceptance ────────────────────────────────────────────────

	public function test_meta_key_field_passes_through(): void {
		// A field named `meta_key` is NOT in any bucket and a suffix-match would have caught it.
		$response = array( 'meta_key' => 'last_login_ip' );
		$out      = ( new ResponseRedactor() )->redact( $response );
		$this->assertSame( 'last_login_ip', $out['meta_key'] );
	}

	public function test_cache_key_field_passes_through(): void {
		$response = array( 'cache_key' => 'transient_xyz' );
		$out      = ( new ResponseRedactor() )->redact( $response );
		$this->assertSame( 'transient_xyz', $out['cache_key'] );
	}

	public function test_blog_post_body_with_word_password_passes_through(): void {
		$response = array(
			'post_content' => 'In this guide we cover how to choose a strong password for your account.',
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame(
			'In this guide we cover how to choose a strong password for your account.',
			$out['post_content']
		);
	}

	public function test_comment_body_with_email_in_text_passes_through(): void {
		$response = array(
			'comment_content' => 'Reply to jacob@willow.se for more info.',
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame( 'Reply to jacob@willow.se for more info.', $out['comment_content'] );
	}

	public function test_bucket1_cannot_be_disabled_via_master_toggle(): void {
		update_option( RedactionConfig::OPTION_MASTER_ENABLED, false );

		$out = ( new ResponseRedactor() )->redact( array( 'password' => 'secret' ) );
		$this->assertSame( '[redacted:bucket_1]', $out['password'] );
	}

	public function test_bucket1_cannot_be_disabled_via_per_ability_exemption(): void {
		// Even if both Bucket 2 and Bucket 3 exemptions list the ability, Bucket 1 still redacts.
		update_option( RedactionConfig::OPTION_BUCKET2_EXEMPTIONS, array( 'foo/bar' ) );
		update_option( RedactionConfig::OPTION_BUCKET3_EXEMPTIONS, array( 'foo/bar' ) );

		$out = ( new ResponseRedactor( 'foo/bar' ) )->redact(
			array( 'password' => 'secret' )
		);
		$this->assertSame( '[redacted:bucket_1]', $out['password'] );
	}

	// ── Counts ────────────────────────────────────────────────────────────────

	public function test_counts_reflect_redactions_per_bucket(): void {
		$response = array(
			'password' => 'a',                     // b1
			'email'    => 'b@c.com',               // b3
			'phone'    => '+46',                   // b3
			'card_number' => '4242424242424242',   // b2
		);

		$redactor = new ResponseRedactor();
		$redactor->redact( $response );
		$counts = $redactor->get_counts();

		$this->assertSame( 1, $counts[ RedactionConfig::BUCKET_SECRETS ] );
		$this->assertSame( 1, $counts[ RedactionConfig::BUCKET_PAYMENT ] );
		$this->assertSame( 2, $counts[ RedactionConfig::BUCKET_CONTACT ] );
	}
}
