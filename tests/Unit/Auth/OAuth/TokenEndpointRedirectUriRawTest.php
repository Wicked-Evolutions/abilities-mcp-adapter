<?php
/**
 * M-4: TokenEndpoint must NOT esc_url_raw() the redirect_uri before the
 * timing-safe compare in AuthorizationCodeStore::consume().
 *
 * Pre-fix:
 *   $redirect_uri = esc_url_raw( $params['redirect_uri'] ?? '' );
 *   ...
 *   AuthorizationCodeStore::consume( $code, $client_id, $redirect_uri, $verifier );
 *
 * The storage path (AuthorizeRequestValidator::str()) only trim()s the raw value.
 * Any character esc_url_raw mutates (or any rule change) breaks hash_equals on
 * exchange — the operator gets invalid_grant despite a perfectly valid code.
 *
 * After fix: raw input is read with only trim() applied, matching the storage path.
 *
 * The test drives TokenEndpoint::handle_post() end-to-end with a redirect_uri
 * containing a character esc_url_raw mutates (a literal space). With a stub
 * $wpdb whose stored redirect_uri is the un-mutated value, consume() must
 * succeed → token_success → TokenResponseSentinel with status 200.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationCodeStore;
use WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints\TokenEndpoint;
use WickedEvolutions\McpAdapter\Tests\TokenResponseSentinel;

final class TokenEndpointRedirectUriRawTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		$this->original_wpdb = $GLOBALS['wpdb'];
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->original_wpdb;
	}

	/**
	 * The token endpoint must accept a raw redirect_uri string verbatim (post-trim)
	 * — no esc_url_raw mutation.
	 *
	 * If TokenEndpoint applied esc_url_raw, the encoded form would no longer
	 * hash_equals the stored raw form, AuthorizationCodeStore::consume() would
	 * return null, and the endpoint would call token_error('invalid_grant', ..., 400).
	 */
	public function test_consume_succeeds_with_unmutated_raw_redirect_uri(): void {
		$verifier = str_repeat( 'a', 50 );
		// Compute the matching code_challenge (S256) the way the validator does.
		$challenge = AuthorizationCodeStore::compute_challenge( $verifier );

		// A redirect_uri that esc_url_raw would mutate at least minimally
		// (space → +, fragment removal, control char strip). Use a value
		// containing a literal space to maximise visibility.
		$raw_redirect = 'https://client.example.com/cb?x=a b';

		$plaintext_code = bin2hex( random_bytes( 16 ) );

		$GLOBALS['wpdb'] = $this->install_consume_wpdb( $plaintext_code, $raw_redirect, $challenge );

		$req = new \WP_REST_Request();
		$req->set_param( 'grant_type', 'authorization_code' );
		$req->set_param( 'code', $plaintext_code );
		$req->set_param( 'client_id', 'cl_test' );
		$req->set_param( 'redirect_uri', $raw_redirect );
		$req->set_param( 'code_verifier', $verifier );

		try {
			TokenEndpoint::handle_post( $req );
			$this->fail( 'Expected TokenResponseSentinel' );
		} catch ( TokenResponseSentinel $e ) {
			$this->assertSame(
				200,
				$e->status,
				'redirect_uri must round-trip without esc_url_raw mutation: got status ' . $e->status . ', body=' . json_encode( $e->body )
			);
			$this->assertArrayHasKey( 'access_token', $e->body );
		}
	}

	/**
	 * Sanity guard: confirm esc_url_raw really does mutate the chosen test value.
	 * If WP's esc_url_raw is patched in the future to be a no-op on this input,
	 * this test would silently pass even with the bug present.
	 */
	public function test_chosen_redirect_uri_would_be_mutated_by_esc_url_raw(): void {
		$raw = 'https://client.example.com/cb?x=a b';
		$this->assertNotSame(
			$raw,
			esc_url_raw( $raw ),
			'Test sentinel: this redirect_uri value must be mutated by esc_url_raw — otherwise the M-4 test cannot detect a regression'
		);
	}

	/**
	 * Stub $wpdb that:
	 *   - Returns a code row matching $code with stored redirect_uri = $expected_raw.
	 *   - Accepts the mark-as-used UPDATE.
	 *   - Accepts the access/refresh INSERTs from TokenStore::issue().
	 *
	 * No client lookup is needed — TokenEndpoint::handle_auth_code calls
	 * ClientRegistry::find() before consume(); we satisfy that with a row whose
	 * client_id matches.
	 */
	private function install_consume_wpdb( string $code, string $expected_redirect, string $challenge ): object {
		$code_hash = hash( 'sha256', $code );

		return new class( $code_hash, $expected_redirect, $challenge ) {
			public string $prefix    = 'wp_';
			public int    $insert_id = 99;
			private string $code_hash;
			private string $expected_redirect;
			private string $challenge;
			private int    $get_row_calls = 0;

			public function __construct( string $h, string $r, string $c ) {
				$this->code_hash         = $h;
				$this->expected_redirect = $r;
				$this->challenge         = $c;
			}

			public function prepare( $q, ...$a ) { return $q; }
			public function get_var( $q )         { return null; }
			public function get_results( $q )     { return array(); }
			public function query( $sql )         { return true; }

			public function get_row( $q ) {
				$this->get_row_calls++;
				// Call 1: ClientRegistry::find() — return a non-revoked client.
				if ( $this->get_row_calls === 1 ) {
					return (object) [
						'client_id'     => 'cl_test',
						'client_name'   => 'Test',
						'redirect_uris' => json_encode( [ $this->expected_redirect ] ),
						'revoked_at'    => null,
					];
				}
				// Call 2: AuthorizationCodeStore::consume() lookup.
				if ( $this->get_row_calls === 2 ) {
					return (object) [
						'id'                    => 1,
						'code_hash'             => $this->code_hash,
						'client_id'             => 'cl_test',
						'user_id'               => 7,
						'redirect_uri'          => $this->expected_redirect,
						'scope'                 => 'abilities:content:read',
						'resource'              => 'https://example.com/wp-json/mcp/mcp-adapter-default-server',
						'code_challenge'        => $this->challenge,
						'code_challenge_method' => 'S256',
						'expires_at'            => gmdate( 'Y-m-d H:i:s', time() + 600 ),
						'used'                  => 0,
					];
				}
				return null;
			}

			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null )                  { return 1; }
		};
	}
}
