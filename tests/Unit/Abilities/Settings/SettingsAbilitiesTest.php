<?php
/**
 * Unit tests for the AI-callable settings abilities (DB-3).
 *
 * Focus on the in-chat 1/2 confirmation flow and the no-friction paths.
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Abilities\Settings;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Abilities\Settings\SettingsAbilities;
use WickedEvolutions\McpAdapter\Settings\SafetySettingsRepository as Repo;

final class SettingsAbilitiesTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_options']    = array();
		$GLOBALS['wp_test_transients'] = array();
		$GLOBALS['wp_test_abilities']  = array();
		unset( $_SERVER['HTTP_MCP_SESSION_ID'] );

		// Register abilities used by exempt-ability-from-bucket3 tests.
		// guard_known_ability_name() calls wp_get_ability(); without registration
		// it returns null and the guard rejects before the test logic runs.
		wp_register_ability( 'users/list', array() );
	}

	public function test_get_redaction_list_returns_full_state(): void {
		$out = SettingsAbilities::execute_get_redaction_list();
		$this->assertArrayHasKey( 'master_enabled', $out );
		$this->assertArrayHasKey( 'bucket1', $out );
		$this->assertArrayHasKey( 'bucket2', $out );
		$this->assertArrayHasKey( 'bucket3', $out );
		$this->assertTrue( $out['master_enabled'] );
		$this->assertContains( 'password', $out['bucket1'] );
		$this->assertContains( 'email', $out['bucket3']['active'] );
	}

	public function test_add_redaction_keyword_strengthens_without_friction(): void {
		$out = SettingsAbilities::execute_add_redaction_keyword( array(
			'keyword' => 'gravity_forms_secret',
			'bucket'  => 3,
		) );
		$this->assertTrue( $out['success'] );
		$this->assertTrue( $out['added'] );
		$this->assertContains( 'gravity_forms_secret', Repo::get_active_keywords( Repo::BUCKET_CONTACT ) );
	}

	public function test_remove_default_bucket3_keyword_first_call_returns_token(): void {
		$out = SettingsAbilities::execute_remove_default_bucket3_keyword( array( 'keyword' => 'email' ) );

		$this->assertFalse( $out['success'] );
		$this->assertTrue( $out['confirmation_required'] );
		$this->assertNotEmpty( $out['token'] );
		$this->assertStringContainsString( 'email', $out['summary'] );
		$this->assertCount( 2, $out['options'] );
		$this->assertContains( 'email', Repo::get_active_keywords( Repo::BUCKET_CONTACT ), 'No mutation on first call.' );
	}

	public function test_remove_default_bucket3_keyword_with_valid_token_executes(): void {
		$first = SettingsAbilities::execute_remove_default_bucket3_keyword( array( 'keyword' => 'email' ) );
		$this->assertTrue( $first['confirmation_required'] );

		$second = SettingsAbilities::execute_remove_default_bucket3_keyword( array(
			'keyword'            => 'email',
			'confirmation_token' => $first['token'],
		) );
		$this->assertTrue( $second['success'] );
		$this->assertNotContains( 'email', Repo::get_active_keywords( Repo::BUCKET_CONTACT ) );
	}

	public function test_remove_default_bucket3_keyword_token_is_one_time(): void {
		$first = SettingsAbilities::execute_remove_default_bucket3_keyword( array( 'keyword' => 'email' ) );

		$second = SettingsAbilities::execute_remove_default_bucket3_keyword( array(
			'keyword'            => 'email',
			'confirmation_token' => $first['token'],
		) );
		$this->assertTrue( $second['success'] );

		// Replay with the same token must fail.
		$third = SettingsAbilities::execute_remove_default_bucket3_keyword( array(
			'keyword'            => 'email',
			'confirmation_token' => $first['token'],
		) );
		$this->assertFalse( $third['success'] );
		$this->assertStringContainsString( 'unknown', strtolower( $third['message'] ) );
	}

	public function test_remove_default_bucket3_keyword_rejects_param_swap(): void {
		// Mint a token for `email`, then try to use it to remove `phone`.
		$first = SettingsAbilities::execute_remove_default_bucket3_keyword( array( 'keyword' => 'email' ) );

		$swap = SettingsAbilities::execute_remove_default_bucket3_keyword( array(
			'keyword'            => 'phone',
			'confirmation_token' => $first['token'],
		) );
		$this->assertFalse( $swap['success'] );
		$this->assertStringContainsString( 'match', strtolower( $swap['message'] ) );

		// Both keywords still present.
		$active = Repo::get_active_keywords( Repo::BUCKET_CONTACT );
		$this->assertContains( 'email', $active );
		$this->assertContains( 'phone', $active );
	}

	public function test_exempt_ability_from_bucket3_first_call_returns_token(): void {
		$out = SettingsAbilities::execute_exempt_ability_from_bucket3( array( 'ability_name' => 'users/list' ) );
		$this->assertTrue( $out['confirmation_required'] );
		$this->assertNotEmpty( $out['token'] );
		$this->assertNotContains( 'users/list', Repo::get_exemptions( Repo::BUCKET_CONTACT ) );
	}

	public function test_exempt_ability_from_bucket3_with_valid_token_succeeds(): void {
		$first = SettingsAbilities::execute_exempt_ability_from_bucket3( array( 'ability_name' => 'users/list' ) );

		$second = SettingsAbilities::execute_exempt_ability_from_bucket3( array(
			'ability_name'       => 'users/list',
			'confirmation_token' => $first['token'],
		) );
		$this->assertTrue( $second['success'] );
		$this->assertContains( 'users/list', Repo::get_exemptions( Repo::BUCKET_CONTACT ) );
	}

	public function test_unexempt_strengthens_without_friction(): void {
		Repo::add_exemption( Repo::BUCKET_CONTACT, 'users/list' );
		$out = SettingsAbilities::execute_unexempt_ability_from_bucket3( array( 'ability_name' => 'users/list' ) );
		$this->assertTrue( $out['success'] );
		$this->assertTrue( $out['removed'] );
		$this->assertNotContains( 'users/list', Repo::get_exemptions( Repo::BUCKET_CONTACT ) );
	}

	public function test_restore_defaults_strengthens_without_friction(): void {
		Repo::add_custom_keyword( Repo::BUCKET_CONTACT, 'gravity_forms_secret' );
		Repo::remove_default_keyword( Repo::BUCKET_CONTACT, 'email' );

		$out = SettingsAbilities::execute_restore_redaction_defaults();
		$this->assertTrue( $out['success'] );
		$this->assertEmpty( Repo::get_custom_keywords( Repo::BUCKET_CONTACT ) );
		$this->assertContains( 'email', Repo::get_active_keywords( Repo::BUCKET_CONTACT ) );
	}

	public function test_remove_custom_keyword_strengthens_without_friction(): void {
		Repo::add_custom_keyword( Repo::BUCKET_CONTACT, 'temp_field' );
		$out = SettingsAbilities::execute_remove_custom_keyword( array(
			'keyword' => 'temp_field',
			'bucket'  => 3,
		) );
		$this->assertTrue( $out['success'] );
		$this->assertTrue( $out['removed'] );
	}

	// --- B.1: Bucket-membership pre-check on remove-default-bucket3-keyword ---

	public function test_b1_rejects_bucket2_card_number_without_minting_token(): void {
		$out = SettingsAbilities::execute_remove_default_bucket3_keyword( array( 'keyword' => 'card_number' ) );

		$this->assertFalse( $out['success'] );
		$this->assertFalse( $out['confirmation_required'] );
		$this->assertArrayNotHasKey( 'token', $out );
		$this->assertStringContainsString( 'Bucket 2', $out['message'] );
		$this->assertStringContainsString( 'Admin', $out['message'] );
		// Repo state unchanged.
		$this->assertContains( 'card_number', Repo::get_active_keywords( Repo::BUCKET_PAYMENT ) );
	}

	public function test_b1_rejects_bucket2_ssn_without_minting_token(): void {
		$out = SettingsAbilities::execute_remove_default_bucket3_keyword( array( 'keyword' => 'ssn' ) );

		$this->assertFalse( $out['success'] );
		$this->assertFalse( $out['confirmation_required'] );
		$this->assertArrayNotHasKey( 'token', $out );
		$this->assertStringContainsString( 'Bucket 2', $out['message'] );
	}

	public function test_b1_rejects_bucket2_tax_id_without_minting_token(): void {
		$out = SettingsAbilities::execute_remove_default_bucket3_keyword( array( 'keyword' => 'tax_id' ) );

		$this->assertFalse( $out['success'] );
		$this->assertFalse( $out['confirmation_required'] );
		$this->assertArrayNotHasKey( 'token', $out );
		$this->assertStringContainsString( 'Bucket 2', $out['message'] );
	}

	public function test_b1_rejects_unknown_keyword_without_minting_token(): void {
		$out = SettingsAbilities::execute_remove_default_bucket3_keyword( array( 'keyword' => 'not_a_real_keyword' ) );

		$this->assertFalse( $out['success'] );
		$this->assertFalse( $out['confirmation_required'] );
		$this->assertArrayNotHasKey( 'token', $out );
		$this->assertStringContainsString( 'not in any default redaction list', $out['message'] );
		$this->assertStringContainsString( 'remove-custom-keyword', $out['message'] );
	}

	public function test_b1_rejects_empty_keyword_without_minting_token(): void {
		$out = SettingsAbilities::execute_remove_default_bucket3_keyword( array( 'keyword' => '' ) );

		$this->assertFalse( $out['success'] );
		$this->assertFalse( $out['confirmation_required'] );
		$this->assertArrayNotHasKey( 'token', $out );
		$this->assertStringContainsString( 'non-empty', $out['message'] );
	}

	public function test_b1_happy_path_bucket3_keyword_still_mints_token(): void {
		// Bucket 3 default — should still flow through the confirmation path.
		$out = SettingsAbilities::execute_remove_default_bucket3_keyword( array( 'keyword' => 'phone' ) );

		$this->assertFalse( $out['success'] );
		$this->assertTrue( $out['confirmation_required'] );
		$this->assertNotEmpty( $out['token'] );
		$this->assertStringContainsString( 'phone', $out['summary'] );
	}

	public function test_b1_bucket2_keyword_with_token_still_rejected(): void {
		// Even if a (somehow-obtained) token were presented for a Bucket 2 keyword,
		// the pre-check fires before token consumption.
		$out = SettingsAbilities::execute_remove_default_bucket3_keyword( array(
			'keyword'            => 'card_number',
			'confirmation_token' => 'whatever-token-the-attacker-supplied',
		) );

		$this->assertFalse( $out['success'] );
		$this->assertStringContainsString( 'Bucket 2', $out['message'] );
		// The Bucket 2 default is still in place.
		$this->assertContains( 'card_number', Repo::get_active_keywords( Repo::BUCKET_PAYMENT ) );
	}

	public function test_b1_bucket3_case_insensitive_match(): void {
		// Inputs are lowercased before comparison.
		$out = SettingsAbilities::execute_remove_default_bucket3_keyword( array( 'keyword' => 'EMAIL' ) );

		$this->assertFalse( $out['success'] );
		$this->assertTrue( $out['confirmation_required'] );
	}

	// --- B.1: exempt-ability-from-bucket3 ability-name guard ---
	//
	// `wp_get_ability()` is not stubbed in unit tests, so the guard fail-opens
	// per its documented contract. The existing happy-path test
	// (test_exempt_ability_from_bucket3_first_call_returns_token) covers that.
	// When the function exists at runtime on real WP, unknown ability names
	// short-circuit; integration coverage for that path lives downstream.

	public function test_b1_exempt_ability_rejects_empty_name(): void {
		$out = SettingsAbilities::execute_exempt_ability_from_bucket3( array( 'ability_name' => '' ) );

		$this->assertFalse( $out['success'] );
		$this->assertFalse( $out['confirmation_required'] );
		$this->assertArrayNotHasKey( 'token', $out );
		$this->assertStringContainsString( 'non-empty', $out['message'] );
	}
}
