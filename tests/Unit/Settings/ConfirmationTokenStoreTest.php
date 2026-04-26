<?php
/**
 * Unit tests for ConfirmationTokenStore.
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Settings;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Settings\ConfirmationTokenStore as Store;

final class ConfirmationTokenStoreTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_transients'] = array();
	}

	public function test_mint_returns_non_empty_token(): void {
		$token = Store::mint( 'sess1', 'settings/remove-default-bucket3-keyword', array( 'keyword' => 'email' ) );
		$this->assertIsString( $token );
		$this->assertNotEmpty( $token );
	}

	public function test_consume_valid_token_succeeds(): void {
		$params = array( 'keyword' => 'email' );
		$token  = Store::mint( 'sess1', 'ability_a', $params );

		$result = Store::consume( $token, 'sess1', 'ability_a', $params );
		$this->assertTrue( $result );
	}

	public function test_token_is_one_time(): void {
		$params = array( 'keyword' => 'email' );
		$token  = Store::mint( 'sess1', 'ability_a', $params );

		$first  = Store::consume( $token, 'sess1', 'ability_a', $params );
		$second = Store::consume( $token, 'sess1', 'ability_a', $params );

		$this->assertTrue( $first );
		$this->assertInstanceOf( \WP_Error::class, $second );
		$this->assertSame( 'token_unknown', $second->get_error_code() );
	}

	public function test_missing_token_rejected(): void {
		$err = Store::consume( '', 'sess1', 'ability_a', array() );
		$this->assertInstanceOf( \WP_Error::class, $err );
		$this->assertSame( 'missing_token', $err->get_error_code() );
	}

	public function test_session_mismatch_rejected(): void {
		$params = array( 'keyword' => 'email' );
		$token  = Store::mint( 'sess1', 'ability_a', $params );

		$err = Store::consume( $token, 'sess_other', 'ability_a', $params );
		$this->assertInstanceOf( \WP_Error::class, $err );
		$this->assertSame( 'session_mismatch', $err->get_error_code() );
	}

	public function test_ability_mismatch_rejected(): void {
		$params = array( 'keyword' => 'email' );
		$token  = Store::mint( 'sess1', 'ability_a', $params );

		$err = Store::consume( $token, 'sess1', 'ability_b', $params );
		$this->assertInstanceOf( \WP_Error::class, $err );
		$this->assertSame( 'ability_mismatch', $err->get_error_code() );
	}

	public function test_params_mismatch_rejected(): void {
		$token = Store::mint( 'sess1', 'ability_a', array( 'keyword' => 'email' ) );

		$err = Store::consume( $token, 'sess1', 'ability_a', array( 'keyword' => 'phone' ) );
		$this->assertInstanceOf( \WP_Error::class, $err );
		$this->assertSame( 'params_mismatch', $err->get_error_code() );
	}

	public function test_failed_lookup_invalidates_token_anyway(): void {
		// Replay protection: even when consume() fails because of a binding
		// mismatch, the transient must be deleted so an attacker cannot
		// retry the same token after fixing the mismatch.
		$params = array( 'keyword' => 'email' );
		$token  = Store::mint( 'sess1', 'ability_a', $params );

		Store::consume( $token, 'sess_wrong', 'ability_a', $params );

		$err = Store::consume( $token, 'sess1', 'ability_a', $params );
		$this->assertInstanceOf( \WP_Error::class, $err );
		$this->assertSame( 'token_unknown', $err->get_error_code() );
	}
}
