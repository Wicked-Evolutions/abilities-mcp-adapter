<?php
/**
 * H-2: Client authentication on /oauth/revoke (RFC 7009 §2.1).
 *
 * Pre-fix: RevokeEndpoint::handle_post accepted any token+revoke request
 * without verifying the caller's client_id. Anyone who learned a token could
 * revoke it. Also, revoking a refresh token left access tokens live.
 *
 * After fix:
 *  - client_id in the POST body must match the client_id stored on the token.
 *  - Mismatch silently succeeds (no info leak) but does NOT revoke.
 *  - Revoking a refresh token cascades through revoke_family (access tokens die too).
 *  - Unknown / not-found token silently succeeds (RFC 7009 §2.2).
 *
 * Note on public clients: all MCP-protocol clients register via DCR without a
 * client_secret (token_endpoint_auth_method: none). For these clients, RFC 7009
 * §2.1 "client authentication" is satisfied by presenting the client_id that was
 * issued at registration time. The binding check here is that proof of possession.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Endpoints
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Endpoints;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints\RevokeEndpoint;
use WickedEvolutions\McpAdapter\Tests\TokenResponseSentinel;

final class RevokeEndpointClientAuthTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		parent::setUp();
		$this->original_wpdb        = $GLOBALS['wpdb'];
		$GLOBALS['wp_test_transients'] = array();
		unset( $_SERVER['REMOTE_ADDR'] );
		$_SERVER['REMOTE_ADDR'] = '10.0.0.1';
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb']               = $this->original_wpdb;
		$GLOBALS['wp_test_transients'] = array();
		unset( $_SERVER['REMOTE_ADDR'] );
		parent::tearDown();
	}

	/** Build a request with given params. */
	private function make_request( array $params ): \WP_REST_Request {
		$req = new \WP_REST_Request();
		foreach ( $params as $k => $v ) {
			$req->set_param( $k, $v );
		}
		return $req;
	}

	/**
	 * Install a $wpdb stub whose get_row returns a pre-built access token meta row
	 * (for find_token_meta) and records update() calls.
	 */
	private function install_access_token_meta( string $client_id = 'cl_abc' ): object {
		$calls = new \stdClass();
		$calls->update_count  = 0;
		$calls->query_count   = 0;

		$meta_row             = new \stdClass();
		$meta_row->client_id  = $client_id;
		$meta_row->family_id  = null;
		$meta_row->type       = 'access';

		$access_id_row        = new \stdClass();
		$access_id_row->id    = 42;

		$GLOBALS['wpdb'] = new class( $meta_row, $access_id_row, $calls ) {
			public string $prefix = 'wp_';
			private object $meta_row;
			private object $access_id_row;
			private object $calls;
			private int    $get_row_call = 0;

			public function __construct( object $m, object $a, object $c ) {
				$this->meta_row      = $m;
				$this->access_id_row = $a;
				$this->calls         = $c;
			}

			public function prepare( $q, ...$a ) { return $q; }

			public function get_row( $q ) {
				$this->get_row_call++;
				// First call: find_token_meta refresh-table check → null (it's an access token).
				// Second call: find_token_meta access-table check → meta_row.
				// Third call (from revoke_by_plaintext): refresh-table cascade check → null.
				// Fourth call (from revoke_by_plaintext): access-table id lookup → access_id_row.
				return match ( $this->get_row_call ) {
					1 => null,           // not a refresh token
					2 => $this->meta_row, // is an access token
					3 => null,            // no paired refresh
					4 => $this->access_id_row,
					default => null,
				};
			}

			public function get_results( $q ) { return array(); }
			public function get_var( $q )     { return null; }
			public function update( $t, $d, $w, $f = null, $wf = null ) {
				$this->calls->update_count++;
				return 1;
			}
			public function insert( $t, $d, $f = null ) { return 1; }
			public function query( $sql ) {
				$this->calls->query_count++;
				return true;
			}
		};

		return $calls;
	}

	public function test_correct_client_id_allows_revocation(): void {
		$calls = $this->install_access_token_meta( 'cl_abc' );
		$req   = $this->make_request( array( 'token' => 'tok_plaintext', 'client_id' => 'cl_abc' ) );

		try {
			RevokeEndpoint::handle_post( $req );
			$this->fail( 'Expected TokenResponseSentinel' );
		} catch ( TokenResponseSentinel $e ) {
			$this->assertSame( 200, $e->status );
			$this->assertSame( 'success', $e->context );
		}

		// Revocation must have fired (update() called on access table).
		$this->assertGreaterThan( 0, $calls->update_count, 'access token must be revoked' );
	}

	public function test_wrong_client_id_silently_succeeds_but_does_not_revoke(): void {
		$calls = $this->install_access_token_meta( 'cl_abc' );
		$req   = $this->make_request( array( 'token' => 'tok_plaintext', 'client_id' => 'cl_attacker' ) );

		try {
			RevokeEndpoint::handle_post( $req );
			$this->fail( 'Expected TokenResponseSentinel' );
		} catch ( TokenResponseSentinel $e ) {
			// RFC 7009: must still return 200.
			$this->assertSame( 200, $e->status );
			$this->assertSame( 'success', $e->context );
		}

		// Revocation must NOT have fired.
		$this->assertSame( 0, $calls->update_count, 'wrong client_id must not trigger revocation' );
	}

	public function test_missing_client_id_silently_succeeds_but_does_not_revoke(): void {
		$calls = $this->install_access_token_meta( 'cl_abc' );
		// No client_id in params.
		$req = $this->make_request( array( 'token' => 'tok_plaintext' ) );

		try {
			RevokeEndpoint::handle_post( $req );
			$this->fail( 'Expected TokenResponseSentinel' );
		} catch ( TokenResponseSentinel $e ) {
			$this->assertSame( 200, $e->status );
		}

		$this->assertSame( 0, $calls->update_count, 'missing client_id must not trigger revocation' );
	}

	public function test_missing_token_returns_200_immediately(): void {
		// No DB access needed — missing token should short-circuit.
		$req = $this->make_request( array() );

		try {
			RevokeEndpoint::handle_post( $req );
			$this->fail( 'Expected TokenResponseSentinel' );
		} catch ( TokenResponseSentinel $e ) {
			$this->assertSame( 200, $e->status );
			$this->assertSame( 'success', $e->context );
		}
	}

	public function test_unknown_token_silently_succeeds(): void {
		// find_token_meta returns null for both tables → token not found.
		$GLOBALS['wpdb'] = new class {
			public string $prefix = 'wp_';
			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )         { return null; }
			public function get_results( $q )     { return array(); }
			public function get_var( $q )         { return null; }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null ) { return 1; }
			public function query( $sql ) { return true; }
		};

		$req = $this->make_request( array( 'token' => 'no_such_token', 'client_id' => 'cl_abc' ) );

		try {
			RevokeEndpoint::handle_post( $req );
			$this->fail( 'Expected TokenResponseSentinel' );
		} catch ( TokenResponseSentinel $e ) {
			$this->assertSame( 200, $e->status );
		}
	}
}
