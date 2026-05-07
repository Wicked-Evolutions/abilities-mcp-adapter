<?php
/**
 * Regression coverage for issue #103 — Bucket 3 redaction matchers must
 * cover prefixed email field variants (admin_email, author_email, etc.)
 * via token-based substring matching, not field-name-EQUALS only.
 *
 * Source: Cold-AI Trinity Test 2026-05-06 (RUN_ID `cold-trinity-2026-05-06T122000Z`).
 * Empirical leaks observed against `multisite/get-site`,
 * `multisite/get-network-settings`, `settings/list`, `comments/list`.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Infrastructure\Redaction;

use WickedEvolutions\McpAdapter\Infrastructure\Redaction\RedactionConfig;
use WickedEvolutions\McpAdapter\Infrastructure\Redaction\ResponseRedactor;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class Bucket3EmailFamilyTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		$GLOBALS['wp_test_options'] = array();
	}

	/**
	 * @return iterable<string,array{0:string,1:string}>
	 */
	public function emailFamilyVariantProvider(): iterable {
		// Variants observed live + likely prefixed forms — every one must
		// redact under default settings. The acceptance gate explicitly
		// names the first four; the rest are anti-regression coverage so
		// the next email-prefix that ships through abilities can't leak.
		yield 'plain email'              => array( 'email', 'jacob@willow.se' );
		yield 'admin_email'              => array( 'admin_email', 'admin@example.com' );
		yield 'author_email'             => array( 'author_email', 'author@example.com' );
		yield 'network_admin_email'      => array( 'network_admin_email', 'super@example.com' );
		yield 'to_email'                 => array( 'to_email', 'to@example.com' );
		yield 'from_email'               => array( 'from_email', 'from@example.com' );
		yield 'customer_email'           => array( 'customer_email', 'cust@example.com' );
		yield 'user_email'               => array( 'user_email', 'user@example.com' );
		yield 'billing_email'            => array( 'billing_email', 'billing@example.com' );
		yield 'shipping_email'           => array( 'shipping_email', 'shipping@example.com' );
		yield 'payment_email'            => array( 'payment_email', 'payment@example.com' );
		yield 'contact_email'            => array( 'contact_email', 'contact@example.com' );
		yield 'reply_to_email'           => array( 'reply_to_email', 'reply@example.com' );
		yield 'bcc_email'                => array( 'bcc_email', 'bcc@example.com' );
		yield 'cc_email'                 => array( 'cc_email', 'cc@example.com' );
		yield 'support_email'            => array( 'support_email', 'support@example.com' );
		yield 'sender_email'             => array( 'sender_email', 'sender@example.com' );
		yield 'recipient_email'          => array( 'recipient_email', 'recipient@example.com' );
		yield 'subscriber_email'         => array( 'subscriber_email', 'subscriber@example.com' );
		yield 'agent_email'              => array( 'agent_email', 'agent@example.com' );
		yield 'email_address'            => array( 'email_address', 'addr@example.com' );
		yield 'kebab admin-email'        => array( 'admin-email', 'admin@example.com' );
		yield 'camel adminEmail'         => array( 'adminEmail', 'admin@example.com' );
		yield 'camel authorEmail'        => array( 'authorEmail', 'author@example.com' );
		yield 'camel customerEmail'      => array( 'customerEmail', 'cust@example.com' );
		yield 'pascal AdminEmail'        => array( 'AdminEmail', 'admin@example.com' );
		yield 'mixed Author_Email'       => array( 'Author_Email', 'author@example.com' );
		yield 'uppercase EMAIL'          => array( 'EMAIL', 'shout@example.com' );
		yield 'uppercase ADMIN_EMAIL'    => array( 'ADMIN_EMAIL', 'shout@example.com' );
	}

	/**
	 * @dataProvider emailFamilyVariantProvider
	 */
	public function test_email_family_variant_redacts_under_default_settings( string $field, string $value ): void {
		$response = array( $field => $value );

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame(
			'[redacted:bucket_3]',
			$out[ $field ],
			sprintf( 'Email-family field "%s" must redact under default settings.', $field )
		);
	}

	public function test_negative_control_master_off_passes_email_family_through(): void {
		// Behaviour-reversal phase: with the master toggle off, every
		// email-family field must pass through unchanged. Pins the fix
		// is conditional, not unconditional-with-extra-steps.
		update_option( RedactionConfig::OPTION_MASTER_ENABLED, false );

		$response = array(
			'admin_email'     => 'admin@example.com',
			'author_email'    => 'author@example.com',
			'customer_email'  => 'cust@example.com',
			'adminEmail'      => 'camel@example.com',
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame( 'admin@example.com',    $out['admin_email'] );
		$this->assertSame( 'author@example.com',   $out['author_email'] );
		$this->assertSame( 'cust@example.com',     $out['customer_email'] );
		$this->assertSame( 'camel@example.com',    $out['adminEmail'] );
	}

	public function test_negative_control_per_ability_exempt_passes_email_family_through(): void {
		// A Bucket 3 exemption for the ability disables email-family
		// matching too — the substring rule lives inside Bucket 3.
		update_option(
			RedactionConfig::OPTION_BUCKET3_EXEMPTIONS,
			array( 'fluent-cart/list-customers' )
		);

		$response = array(
			'admin_email'    => 'admin@example.com',
			'customer_email' => 'cust@example.com',
		);

		$out = ( new ResponseRedactor( 'fluent-cart/list-customers' ) )->redact( $response );

		$this->assertSame( 'admin@example.com', $out['admin_email'] );
		$this->assertSame( 'cust@example.com',  $out['customer_email'] );
	}

	public function test_email_family_redacts_under_meta_list_post_meta_path(): void {
		// Path-aware: email-family redaction fires regardless of which
		// ability produced the response. `meta/list-post-meta` returning
		// a meta value happens to be named `admin_email` must redact.
		$response = array(
			'meta' => array(
				'admin_email'    => 'admin@example.com',
				'admin-email'    => 'admin@example.com',
				'customerEmail'  => 'cust@example.com',
			),
		);

		$out = ( new ResponseRedactor( 'meta/list-post-meta' ) )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['meta']['admin_email'] );
		$this->assertSame( '[redacted:bucket_3]', $out['meta']['admin-email'] );
		$this->assertSame( '[redacted:bucket_3]', $out['meta']['customerEmail'] );
	}

	public function test_token_match_does_not_match_unrelated_substrings(): void {
		// Conservative tokenisation: only exact-token `email` triggers the rule.
		// Plurals and adjacencies pass through.
		$response = array(
			'emails'        => 'plural-not-token',
			'emailable'     => 'adjective-not-token',
			'emailing_user' => 'verb-not-token',
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame( 'plural-not-token',     $out['emails'],        '`emails` is a single non-`email` token; passes.' );
		$this->assertSame( 'adjective-not-token',  $out['emailable'],     '`emailable` is a single non-`email` token; passes.' );
		$this->assertSame( 'verb-not-token',       $out['emailing_user'], '`emailing` does not equal `email`; passes.' );
	}

	public function test_blog_body_with_email_word_in_text_still_passes_through(): void {
		// Substring matching applies to FIELD names, never to free-text bodies.
		// Adversarial: a comment containing the word "email" must not be
		// rewritten — the existing no-regex-over-JSON principle is intact.
		$response = array(
			'comment_content' => 'You can reach us at any admin_email if you need support.',
			'post_content'    => 'Configure your admin_email under settings.',
		);

		$out = ( new ResponseRedactor() )->redact( $response );

		$this->assertSame( 'You can reach us at any admin_email if you need support.', $out['comment_content'] );
		$this->assertSame( 'Configure your admin_email under settings.',                $out['post_content'] );
	}

	public function test_email_family_redaction_increments_bucket3_counter(): void {
		$response = array(
			'admin_email'    => 'a@example.com',
			'author_email'   => 'b@example.com',
			'customer_email' => 'c@example.com',
			'first_name'     => 'Jacob',
		);

		$redactor = new ResponseRedactor();
		$redactor->redact( $response );
		$counts = $redactor->get_counts();

		$this->assertSame( 3, $counts[ RedactionConfig::BUCKET_CONTACT ], 'Each email-family field counts as one Bucket 3 redaction.' );
		$this->assertSame( 0, $counts[ RedactionConfig::BUCKET_SECRETS ] );
		$this->assertSame( 0, $counts[ RedactionConfig::BUCKET_PAYMENT ] );
	}

	public function test_cold_ai_replay_multisite_get_site_admin_email_redacts(): void {
		// Empirical replay of the exact shape `multisite/get-site` returned
		// to the cold-AI test on wickedevolutions, with the leaking field
		// inline. Pins the fix against the original failing call.
		$response = array(
			'site' => array(
				'blog_id'     => 1,
				'domain'      => 'example.com',
				'path'        => '/',
				'admin_email' => 'jacob@willow.se',
				'public'      => 1,
			),
		);

		$out = ( new ResponseRedactor( 'multisite/get-site' ) )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['site']['admin_email'] );
		$this->assertSame( 'example.com', $out['site']['domain'] );
	}

	public function test_cold_ai_replay_comments_list_author_email_redacts(): void {
		// Empirical replay of the `comments/list` shape.
		$response = array(
			'comments' => array(
				array(
					'comment_ID'   => 5,
					'author_email' => 'visitor@example.com',
					'author_name'  => 'Visitor',
					'comment_content' => 'Nice post.',
				),
			),
		);

		$out = ( new ResponseRedactor( 'comments/list' ) )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['comments'][0]['author_email'] );
		$this->assertSame( 'Visitor',             $out['comments'][0]['author_name'] );
		$this->assertSame( 'Nice post.',          $out['comments'][0]['comment_content'] );
	}

	public function test_cold_ai_replay_settings_list_admin_email_redacts(): void {
		$response = array(
			'settings' => array(
				'blogname'     => 'Test Site',
				'admin_email'  => 'admin@example.com',
				'siteurl'      => 'https://example.com',
			),
		);

		$out = ( new ResponseRedactor( 'settings/list' ) )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['settings']['admin_email'] );
		$this->assertSame( 'Test Site',           $out['settings']['blogname'] );
	}

	public function test_cold_ai_replay_get_network_settings_admin_email_redacts(): void {
		$response = array(
			'network' => array(
				'site_name'   => 'Network',
				'admin_email' => 'super@example.com',
			),
		);

		$out = ( new ResponseRedactor( 'multisite/get-network-settings' ) )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['network']['admin_email'] );
	}
}
