<?php
/**
 * Tests for AuthorizeRequestValidator — implements the H.3.6 + H.3.5 contract.
 *
 * Critical invariants:
 *   - client_id missing/unknown → PRE_REDIRECT_ERROR (NEVER redirect, even with redirect_uri set).
 *   - redirect_uri unregistered → PRE_REDIRECT_ERROR (NEVER redirect).
 *   - state missing or > 256 chars → REDIRECTABLE_ERROR (we have a known-good redirect_uri at this point).
 *   - PKCE / response_type / scope errors → REDIRECTABLE_ERROR.
 *
 * The first two invariants together prove H.3.6: an attacker hitting
 * /oauth/authorize with garbage cannot trigger a wp-login redirect that
 * would leak auth state.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\AuthorizeRequestValidator;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\AuthorizeValidationResult;

final class AuthorizeRequestValidatorTest extends TestCase {

	private const RESOURCE = 'https://example.com/wp-json/mcp/mcp-adapter-default-server';

	protected function setUp(): void {
		// Each test starts with a clean stub registry of "registered clients".
		$GLOBALS['wp_test_oauth_registered_clients'] = array();
	}

	// ─── H.3.6 — pre-login validation ─────────────────────────────────────────────

	public function test_missing_client_id_returns_pre_redirect_error(): void {
		$result = AuthorizeRequestValidator::validate(
			array( 'redirect_uri' => 'http://127.0.0.1/cb', 'response_type' => 'code' ),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_pre_redirect_error(), 'No client_id MUST never redirect (H.3.6).' );
		$this->assertSame( 'invalid_request', $result->error_code );
	}

	public function test_unknown_client_id_returns_pre_redirect_error_even_with_valid_redirect_uri(): void {
		// No client registered for the given client_id → PRE_REDIRECT_ERROR, NEVER a redirect.
		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'     => 'unknown-client-id',
				'redirect_uri'  => 'http://127.0.0.1/cb',
				'response_type' => 'code',
				'scope'         => 'abilities:read',
				'state'         => 'abc',
				'code_challenge'=> 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_pre_redirect_error(), 'Unknown client MUST never redirect (H.3.6).' );
		$this->assertSame( 'invalid_client', $result->error_code );
	}

	public function test_unregistered_redirect_uri_returns_pre_redirect_error(): void {
		$client_id = 'client-1';
		$this->register_client( $client_id, array( 'http://127.0.0.1/cb' ) );

		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'     => $client_id,
				'redirect_uri'  => 'https://attacker.example.com/x',
				'response_type' => 'code',
				'scope'         => 'abilities:read',
				'state'         => 'abc',
				'code_challenge'=> 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_pre_redirect_error(), 'Unregistered redirect_uri MUST never redirect.' );
		$this->assertSame( 'invalid_request', $result->error_code );
	}

	// ─── H.3.5 — state parameter ─────────────────────────────────────────────────

	public function test_missing_state_returns_redirectable_error(): void {
		$client_id = 'client-2';
		$this->register_client( $client_id, array( 'http://127.0.0.1/cb' ) );

		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'     => $client_id,
				'redirect_uri'  => 'http://127.0.0.1/cb',
				'response_type' => 'code',
				'scope'         => 'abilities:read',
				'state'         => '',
				'code_challenge'=> 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_redirectable_error() );
		$this->assertSame( 'invalid_request', $result->error_code );
		$this->assertStringContainsString( 'state', $result->error_description );
	}

	public function test_state_longer_than_256_chars_is_rejected(): void {
		$client_id = 'client-3';
		$this->register_client( $client_id, array( 'http://127.0.0.1/cb' ) );

		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'     => $client_id,
				'redirect_uri'  => 'http://127.0.0.1/cb',
				'response_type' => 'code',
				'scope'         => 'abilities:read',
				'state'         => str_repeat( 'a', 257 ),
				'code_challenge'=> 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_redirectable_error() );
		$this->assertSame( 'invalid_request', $result->error_code );
	}

	public function test_state_at_exactly_256_chars_is_accepted(): void {
		$client_id = 'client-4';
		$this->register_client( $client_id, array( 'http://127.0.0.1/cb' ) );

		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'     => $client_id,
				'redirect_uri'  => 'http://127.0.0.1/cb',
				'response_type' => 'code',
				'scope'         => 'abilities:read',
				'state'         => str_repeat( 'a', 256 ),
				'code_challenge'=> 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_ok(), 'state at exactly 256 chars must validate (H.3.5).' );
	}

	// ─── PKCE ────────────────────────────────────────────────────────────────────

	public function test_missing_code_challenge_returns_redirectable_error(): void {
		$client_id = 'client-5';
		$this->register_client( $client_id, array( 'http://127.0.0.1/cb' ) );

		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'     => $client_id,
				'redirect_uri'  => 'http://127.0.0.1/cb',
				'response_type' => 'code',
				'scope'         => 'abilities:read',
				'state'         => 'abc',
				'code_challenge'=> '',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_redirectable_error() );
	}

	public function test_unsupported_code_challenge_method_returns_redirectable_error(): void {
		$client_id = 'client-6';
		$this->register_client( $client_id, array( 'http://127.0.0.1/cb' ) );

		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'             => $client_id,
				'redirect_uri'          => 'http://127.0.0.1/cb',
				'response_type'         => 'code',
				'scope'                 => 'abilities:read',
				'state'                 => 'abc',
				'code_challenge'        => 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
				'code_challenge_method' => 'plain',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_redirectable_error() );
	}

	// ─── response_type ───────────────────────────────────────────────────────────

	public function test_unsupported_response_type_returns_redirectable_error(): void {
		$client_id = 'client-7';
		$this->register_client( $client_id, array( 'http://127.0.0.1/cb' ) );

		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'     => $client_id,
				'redirect_uri'  => 'http://127.0.0.1/cb',
				'response_type' => 'token',
				'scope'         => 'abilities:read',
				'state'         => 'abc',
				'code_challenge'=> 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_redirectable_error() );
		$this->assertSame( 'unsupported_response_type', $result->error_code );
	}

	// ─── scope ────────────────────────────────────────────────────────────────────

	public function test_unknown_scope_returns_redirectable_error(): void {
		$client_id = 'client-8';
		$this->register_client( $client_id, array( 'http://127.0.0.1/cb' ) );

		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'     => $client_id,
				'redirect_uri'  => 'http://127.0.0.1/cb',
				'response_type' => 'code',
				'scope'         => 'abilities:notarealmodule:read',
				'state'         => 'abc',
				'code_challenge'=> 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_redirectable_error() );
		$this->assertSame( 'invalid_scope', $result->error_code );
	}

	public function test_empty_scope_returns_redirectable_error(): void {
		$client_id = 'client-9';
		$this->register_client( $client_id, array( 'http://127.0.0.1/cb' ) );

		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'     => $client_id,
				'redirect_uri'  => 'http://127.0.0.1/cb',
				'response_type' => 'code',
				'scope'         => '',
				'state'         => 'abc',
				'code_challenge'=> 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_redirectable_error() );
		$this->assertSame( 'invalid_scope', $result->error_code );
	}

	public function test_umbrella_scope_is_expanded_to_implicated_scopes(): void {
		$client_id = 'client-10';
		$this->register_client( $client_id, array( 'http://127.0.0.1/cb' ) );

		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'     => $client_id,
				'redirect_uri'  => 'http://127.0.0.1/cb',
				'response_type' => 'code',
				'scope'         => 'abilities:read',
				'state'         => 'abc',
				'code_challenge'=> 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_ok() );
		$this->assertContains( 'abilities:read',         $result->requested_scopes );
		$this->assertContains( 'abilities:content:read', $result->requested_scopes );
	}

	// ─── resource indicator ───────────────────────────────────────────────────────

	public function test_resource_mismatch_returns_redirectable_error(): void {
		$client_id = 'client-11';
		$this->register_client( $client_id, array( 'http://127.0.0.1/cb' ) );

		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'     => $client_id,
				'redirect_uri'  => 'http://127.0.0.1/cb',
				'response_type' => 'code',
				'scope'         => 'abilities:read',
				'state'         => 'abc',
				'code_challenge'=> 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
				'resource'      => 'https://other.example.com/resource',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_redirectable_error() );
		$this->assertSame( 'invalid_target', $result->error_code );
	}

	public function test_missing_resource_defaults_to_site_resource_indicator(): void {
		$client_id = 'client-12';
		$this->register_client( $client_id, array( 'http://127.0.0.1/cb' ) );

		$result = AuthorizeRequestValidator::validate(
			array(
				'client_id'     => $client_id,
				'redirect_uri'  => 'http://127.0.0.1/cb',
				'response_type' => 'code',
				'scope'         => 'abilities:read',
				'state'         => 'abc',
				'code_challenge'=> 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
			),
			self::RESOURCE
		);
		$this->assertTrue( $result->is_ok() );
		$this->assertSame( self::RESOURCE, $result->resource );
	}

	// ─── Helper — register a fake client by stubbing $wpdb->get_row. ─────────────

	private function register_client( string $client_id, array $redirect_uris ): void {
		$registered = $GLOBALS['wp_test_oauth_registered_clients'] ?? array();
		$registered[ $client_id ] = (object) array(
			'client_id'     => $client_id,
			'client_name'   => 'Test bridge ' . $client_id,
			'redirect_uris' => json_encode( $redirect_uris ),
			'scopes'        => 'abilities:read',
		);
		$GLOBALS['wp_test_oauth_registered_clients'] = $registered;

		// Re-bind $wpdb->get_row to return the matching client row.
		$GLOBALS['wpdb'] = new class {
			public string $prefix = 'wp_';
			public function get_row( $query ) {
				// Crude but deterministic: scan the prepared SQL for any registered client_id.
				foreach ( $GLOBALS['wp_test_oauth_registered_clients'] as $cid => $row ) {
					if ( str_contains( (string) $query, $cid ) ) {
						return $row;
					}
				}
				return null;
			}
			public function get_results( $query ) { return array(); }
			public function get_var( $query )     { return null; }
			public function prepare( $query, ...$args ) {
				// Inline %s substitution so test assertions on get_row() can match by client_id.
				$idx = 0;
				return preg_replace_callback(
					'/%s|%d/',
					static function () use ( &$idx, $args ) {
						$v = $args[ $idx ] ?? '';
						$idx++;
						return is_int( $v ) ? (string) $v : "'" . str_replace( "'", "''", (string) $v ) . "'";
					},
					$query
				);
			}
			public function insert( $table, $data, $format = null ) { return 1; }
			public function update( $table, $data, $where, $format = null, $where_format = null ) { return 1; }
			public function query( $sql ) { return true; }
		};
	}
}
