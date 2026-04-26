<?php
/**
 * Unit tests for SafetySettingsRepository.
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Settings;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Settings\SafetySettingsRepository as Repo;

final class SafetySettingsRepositoryTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_options'] = array();
	}

	public function test_master_toggle_default_on(): void {
		$this->assertTrue( Repo::is_master_enabled() );
	}

	public function test_master_toggle_can_be_disabled_then_re_enabled(): void {
		Repo::set_master_enabled( false );
		$this->assertFalse( Repo::is_master_enabled() );
		Repo::set_master_enabled( true );
		$this->assertTrue( Repo::is_master_enabled() );
	}

	public function test_bucket1_keywords_are_hardcoded_and_non_empty(): void {
		$kws = Repo::bucket1_default_keywords();
		$this->assertNotEmpty( $kws );
		$this->assertContains( 'password', $kws );
		$this->assertContains( 'auth_token', $kws );
	}

	public function test_add_custom_bucket3_keyword(): void {
		$result = Repo::add_custom_keyword( Repo::BUCKET_CONTACT, 'gravity_forms_secret' );
		$this->assertTrue( $result );
		$this->assertContains( 'gravity_forms_secret', Repo::get_active_keywords( Repo::BUCKET_CONTACT ) );
	}

	public function test_add_custom_bucket2_keyword(): void {
		$result = Repo::add_custom_keyword( Repo::BUCKET_PAYMENT, 'wallet_id' );
		$this->assertTrue( $result );
		$this->assertContains( 'wallet_id', Repo::get_active_keywords( Repo::BUCKET_PAYMENT ) );
	}

	public function test_cannot_add_keyword_to_bucket1(): void {
		$result = Repo::add_custom_keyword( Repo::BUCKET_SECRETS, 'whatever' );
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'bucket1_locked', $result->get_error_code() );
	}

	public function test_invalid_bucket_rejected(): void {
		$result = Repo::add_custom_keyword( 9, 'whatever' );
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'invalid_bucket', $result->get_error_code() );
	}

	public function test_empty_keyword_rejected(): void {
		$result = Repo::add_custom_keyword( Repo::BUCKET_CONTACT, '   ' );
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'empty_keyword', $result->get_error_code() );
	}

	public function test_remove_custom_keyword_returns_false_for_unknown(): void {
		$result = Repo::remove_custom_keyword( Repo::BUCKET_CONTACT, 'never_added' );
		$this->assertFalse( $result );
	}

	public function test_remove_custom_keyword_removes_added_entry(): void {
		Repo::add_custom_keyword( Repo::BUCKET_CONTACT, 'foo_secret' );
		$this->assertContains( 'foo_secret', Repo::get_custom_keywords( Repo::BUCKET_CONTACT ) );
		$this->assertTrue( Repo::remove_custom_keyword( Repo::BUCKET_CONTACT, 'foo_secret' ) );
		$this->assertNotContains( 'foo_secret', Repo::get_custom_keywords( Repo::BUCKET_CONTACT ) );
	}

	public function test_remove_default_bucket3_keyword_marks_as_removed(): void {
		$this->assertTrue( in_array( 'email', Repo::get_active_keywords( Repo::BUCKET_CONTACT ), true ) );
		$this->assertTrue( Repo::remove_default_keyword( Repo::BUCKET_CONTACT, 'email' ) );
		$this->assertNotContains( 'email', Repo::get_active_keywords( Repo::BUCKET_CONTACT ) );
		$this->assertContains( 'email', Repo::get_removed_defaults( Repo::BUCKET_CONTACT ) );
	}

	public function test_remove_default_rejects_non_default(): void {
		$result = Repo::remove_default_keyword( Repo::BUCKET_CONTACT, 'not_a_default_keyword' );
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'not_a_default', $result->get_error_code() );
	}

	public function test_re_adding_removed_default_restores_it(): void {
		Repo::remove_default_keyword( Repo::BUCKET_CONTACT, 'email' );
		$this->assertNotContains( 'email', Repo::get_active_keywords( Repo::BUCKET_CONTACT ) );
		Repo::add_custom_keyword( Repo::BUCKET_CONTACT, 'email' );
		$this->assertContains( 'email', Repo::get_active_keywords( Repo::BUCKET_CONTACT ) );
		$this->assertNotContains( 'email', Repo::get_removed_defaults( Repo::BUCKET_CONTACT ) );
	}

	public function test_restore_defaults_clears_customs_and_removed(): void {
		Repo::add_custom_keyword( Repo::BUCKET_CONTACT, 'gravity_forms_secret' );
		Repo::remove_default_keyword( Repo::BUCKET_CONTACT, 'email' );
		Repo::add_custom_keyword( Repo::BUCKET_PAYMENT, 'wallet_id' );

		Repo::restore_defaults();

		$this->assertEmpty( Repo::get_custom_keywords( Repo::BUCKET_CONTACT ) );
		$this->assertEmpty( Repo::get_custom_keywords( Repo::BUCKET_PAYMENT ) );
		$this->assertEmpty( Repo::get_removed_defaults( Repo::BUCKET_CONTACT ) );
		$this->assertContains( 'email', Repo::get_active_keywords( Repo::BUCKET_CONTACT ) );
	}

	public function test_keyword_sanitisation_lowercases_and_strips_invalid_chars(): void {
		Repo::add_custom_keyword( Repo::BUCKET_CONTACT, 'Custom Field!@#' );
		$customs = Repo::get_custom_keywords( Repo::BUCKET_CONTACT );
		$this->assertContains( 'customfield', $customs );
	}

	public function test_exemption_add_remove(): void {
		$this->assertTrue( Repo::add_exemption( Repo::BUCKET_CONTACT, 'users/list' ) );
		$this->assertContains( 'users/list', Repo::get_exemptions( Repo::BUCKET_CONTACT ) );
		$this->assertTrue( Repo::remove_exemption( Repo::BUCKET_CONTACT, 'users/list' ) );
		$this->assertNotContains( 'users/list', Repo::get_exemptions( Repo::BUCKET_CONTACT ) );
	}

	public function test_exemption_idempotent(): void {
		$this->assertTrue( Repo::add_exemption( Repo::BUCKET_CONTACT, 'users/list' ) );
		$this->assertFalse( Repo::add_exemption( Repo::BUCKET_CONTACT, 'users/list' ) );
		$this->assertFalse( Repo::remove_exemption( Repo::BUCKET_CONTACT, 'never-added' ) );
	}

	public function test_exemption_invalid_bucket_rejected(): void {
		$err = Repo::add_exemption( Repo::BUCKET_SECRETS, 'users/list' );
		$this->assertInstanceOf( \WP_Error::class, $err );
		$this->assertSame( 'invalid_bucket', $err->get_error_code() );
	}

	public function test_trusted_proxy_defaults(): void {
		$this->assertFalse( Repo::is_trusted_proxy_enabled() );
		$this->assertSame( Repo::PROXY_MODE_CLOUDFLARE, Repo::get_trusted_proxy_mode() );
		$this->assertSame( '', Repo::get_trusted_proxy_allowlist_raw() );
	}

	public function test_trusted_proxy_round_trip(): void {
		Repo::set_trusted_proxy_enabled( true );
		Repo::set_trusted_proxy_mode( Repo::PROXY_MODE_CUSTOM );
		Repo::set_trusted_proxy_allowlist_raw( "10.0.0.0/8\n192.168.1.1" );

		$this->assertTrue( Repo::is_trusted_proxy_enabled() );
		$this->assertSame( Repo::PROXY_MODE_CUSTOM, Repo::get_trusted_proxy_mode() );
		$this->assertStringContainsString( '10.0.0.0/8', Repo::get_trusted_proxy_allowlist_raw() );
	}

	public function test_trusted_proxy_mode_falls_back_to_cloudflare_for_unknown(): void {
		Repo::set_trusted_proxy_mode( 'something_else' );
		$this->assertSame( Repo::PROXY_MODE_CLOUDFLARE, Repo::get_trusted_proxy_mode() );
	}
}
