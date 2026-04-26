<?php

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Infrastructure\Redaction;

use WickedEvolutions\McpAdapter\Infrastructure\Redaction\RedactionConfig;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class RedactionConfigTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		$GLOBALS['wp_test_options'] = array();
	}

	public function test_master_enabled_default_true(): void {
		$this->assertTrue( RedactionConfig::is_master_enabled() );
	}

	public function test_master_enabled_can_be_turned_off(): void {
		update_option( RedactionConfig::OPTION_MASTER_ENABLED, false );
		$this->assertFalse( RedactionConfig::is_master_enabled() );
	}

	public function test_bucket1_keywords_include_credentials(): void {
		$kws = RedactionConfig::bucket1_keywords();
		$this->assertContains( 'password', $kws );
		$this->assertContains( 'user_pass', $kws );
		$this->assertContains( 'api_key', $kws );
		$this->assertContains( 'session_token', $kws );
		$this->assertContains( 'auth_key', $kws );
		// public_key MUST NOT be in Bucket 1 (per principle: public keys are configurable Bucket 3).
		$this->assertNotContains( 'public_key', $kws );
	}

	public function test_bucket3_default_includes_public_key(): void {
		$kws = RedactionConfig::bucket3_default_keywords();
		$this->assertContains( 'public_key', $kws );
		$this->assertContains( 'email', $kws );
		$this->assertContains( 'user_login', $kws );
	}

	public function test_bucket3_keywords_merges_custom_additions(): void {
		update_option(
			RedactionConfig::OPTION_BUCKET3_KEYWORDS,
			array( 'gravity_forms_secret', 'CustomField' )
		);

		$kws = RedactionConfig::bucket3_keywords();
		$this->assertContains( 'email', $kws );           // default still present.
		$this->assertContains( 'gravity_forms_secret', $kws );
		$this->assertContains( 'customfield', $kws );     // lower-cased.
	}

	public function test_ability_exemption_bucket1_never_exempt(): void {
		update_option( RedactionConfig::OPTION_BUCKET3_EXEMPTIONS, array( 'foo/bar' ) );
		// Bucket 1 NEVER honours an exemption.
		$this->assertFalse( RedactionConfig::is_ability_exempt( 'foo/bar', RedactionConfig::BUCKET_SECRETS ) );
	}

	public function test_ability_exemption_bucket3(): void {
		update_option( RedactionConfig::OPTION_BUCKET3_EXEMPTIONS, array( 'fluent-cart/list-customers' ) );
		$this->assertTrue( RedactionConfig::is_ability_exempt( 'fluent-cart/list-customers', RedactionConfig::BUCKET_CONTACT ) );
		$this->assertFalse( RedactionConfig::is_ability_exempt( 'other/ability', RedactionConfig::BUCKET_CONTACT ) );
	}

	public function test_ability_exemption_bucket2_independent_of_bucket3(): void {
		update_option( RedactionConfig::OPTION_BUCKET3_EXEMPTIONS, array( 'foo/bar' ) );
		// Adding ability to Bucket 3 exemption does not exempt it from Bucket 2.
		$this->assertFalse( RedactionConfig::is_ability_exempt( 'foo/bar', RedactionConfig::BUCKET_PAYMENT ) );

		update_option( RedactionConfig::OPTION_BUCKET2_EXEMPTIONS, array( 'foo/bar' ) );
		$this->assertTrue( RedactionConfig::is_ability_exempt( 'foo/bar', RedactionConfig::BUCKET_PAYMENT ) );
	}
}
