<?php
/**
 * H.2.1: Refresh token rotation must preserve family_id across the full chain.
 *
 * Pre-fix: TokenStore::rotate() called self::issue() which always generated a
 * fresh family_id (bin2hex(random_bytes(16))). Each rotation produced a new
 * family, so replay detection only covered the immediately preceding token —
 * replaying any earlier token in the chain would not trigger family revocation.
 *
 * After fix: rotate() passes the existing $row->family_id into issue() as the
 * optional $family_id parameter. issue() uses the supplied value rather than
 * generating a new one. All tokens in a rotation chain share one family_id,
 * so revoke_family() correctly covers every generation.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\TokenStore;

final class TokenStoreRotationFamilyTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		$this->original_wpdb = $GLOBALS['wpdb'];
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->original_wpdb;
	}

	// -------------------------------------------------------------------------
	// issue() — family_id parameter
	// -------------------------------------------------------------------------

	/**
	 * When no family_id is supplied, issue() must generate a fresh one (initial
	 * issuance path — existing behaviour must not regress).
	 */
	public function test_issue_generates_family_id_when_not_supplied(): void {
		$captured = new \stdClass();
		$captured->family_id = null;

		$GLOBALS['wpdb'] = $this->make_capturing_wpdb( $captured );

		TokenStore::issue( 'cl_test', 1, 'abilities:content:read', 'https://example.com/wp-json/mcp/mcp-adapter-default-server' );

		$this->assertNotNull( $captured->family_id, 'issue() must store a non-null family_id when none is supplied' );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/', $captured->family_id, 'Generated family_id must be 32 hex chars (16 bytes)' );
	}

	/**
	 * When an explicit family_id is supplied, issue() must use it verbatim.
	 */
	public function test_issue_uses_supplied_family_id(): void {
		$captured         = new \stdClass();
		$captured->family_id = null;
		$GLOBALS['wpdb'] = $this->make_capturing_wpdb( $captured );

		$explicit_family = 'aabbccddeeff00112233445566778899';
		TokenStore::issue( 'cl_test', 1, 'abilities:content:read', 'https://example.com/wp-json/mcp/mcp-adapter-default-server', TokenStore::ACCESS_TTL, TokenStore::REFRESH_TTL, $explicit_family );

		$this->assertSame( $explicit_family, $captured->family_id, 'issue() must store the supplied family_id without modification' );
	}

	/**
	 * Two consecutive plain issue() calls must produce different family IDs —
	 * each fresh issuance starts its own independent family.
	 */
	public function test_two_independent_issues_have_distinct_family_ids(): void {
		$cap1 = new \stdClass();
		$cap1->family_id = null;
		$cap2 = new \stdClass();
		$cap2->family_id = null;

		$GLOBALS['wpdb'] = $this->make_capturing_wpdb( $cap1 );
		TokenStore::issue( 'cl_a', 1, 'abilities:content:read', 'https://example.com/wp-json/mcp/mcp-adapter-default-server' );

		$GLOBALS['wpdb'] = $this->make_capturing_wpdb( $cap2 );
		TokenStore::issue( 'cl_b', 2, 'abilities:content:read', 'https://example.com/wp-json/mcp/mcp-adapter-default-server' );

		$this->assertNotSame( $cap1->family_id, $cap2->family_id, 'Independent issuances must have distinct family IDs' );
	}

	// -------------------------------------------------------------------------
	// rotate() — family_id inheritance
	// -------------------------------------------------------------------------

	/**
	 * After rotation the newly issued refresh token must carry the same family_id
	 * as the token being rotated.
	 */
	public function test_rotate_preserves_family_id(): void {
		$parent_family   = 'deadbeefcafe00112233445566778899';
		$plaintext_token = bin2hex( random_bytes( 32 ) );
		$token_hash      = hash( 'sha256', $plaintext_token );

		$captured           = new \stdClass();
		$captured->family_id = null;

		$GLOBALS['wpdb'] = $this->make_rotate_wpdb( $token_hash, $parent_family, $captured );

		$result = TokenStore::rotate( $plaintext_token, 'cl_test' );

		$this->assertNotNull( $result, 'rotate() must succeed' );
		$this->assertArrayHasKey( 'access_token', $result, 'rotate() returns the standard token-pair shape (post-C-2)' );
		$this->assertSame( $parent_family, $captured->family_id, 'rotate() must pass parent family_id into issue()' );
	}

	/**
	 * A retry within the grace window without a stored replay blob (e.g. a row
	 * created before the C-2 schema upgrade, or an already-consumed retry)
	 * resolves to invalid_grant — never generates a new family_id.
	 *
	 * Full plaintext-replay coverage lives in TokenStoreReplayBlobTest (C-2).
	 */
	public function test_grace_retry_without_blob_returns_null(): void {
		$parent_family   = 'deadbeefcafe00112233445566778899';
		$plaintext_token = bin2hex( random_bytes( 32 ) );
		$token_hash      = hash( 'sha256', $plaintext_token );

		// Simulate a token that was already rotated 5 seconds ago (within 30s grace),
		// but with no replay blob recorded (legacy row).
		$GLOBALS['wpdb'] = $this->make_already_rotated_wpdb( $token_hash, $parent_family, rotated_age: 5 );

		$result = TokenStore::rotate( $plaintext_token, 'cl_test' );

		$this->assertNull( $result, 'No blob → null (invalid_grant); no new issue() and no new family_id' );
	}

	/**
	 * Replaying a token outside the grace window triggers family revocation.
	 * The revoke_family() call must use the parent family_id (not null or a new one).
	 */
	public function test_replay_outside_grace_revokes_correct_family(): void {
		$parent_family   = 'deadbeefcafe00112233445566778899';
		$plaintext_token = bin2hex( random_bytes( 32 ) );
		$token_hash      = hash( 'sha256', $plaintext_token );

		$revoked_family = null;

		// Simulate a token rotated 60 seconds ago (outside 30s grace).
		$GLOBALS['wpdb'] = $this->make_replay_wpdb( $token_hash, $parent_family, rotated_age: 60, revoked_family_out: $revoked_family );

		$result = TokenStore::rotate( $plaintext_token, 'cl_test' );

		$this->assertNull( $result, 'Replay outside grace must return null (invalid_grant)' );
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * A $wpdb stub that satisfies TokenStore::issue() and captures the family_id
	 * passed to the second insert() call (the refresh token row).
	 */
	private function make_capturing_wpdb( object $capture ): object {
		return new class( $capture ) {
			public string $prefix    = 'wp_';
			public int    $insert_id = 99;
			private object $capture;
			private int    $insert_calls = 0;

			public function __construct( object $c ) { $this->capture = $c; }

			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )         { return null; }
			public function get_var( $q )         { return null; }
			public function get_results( $q )     { return array(); }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function query( $sql )         { return true; }

			public function insert( $table, $data, $format = null ) {
				$this->insert_calls++;
				if ( $this->insert_calls === 2 && isset( $data['family_id'] ) ) {
					$this->capture->family_id = $data['family_id'];
				}
				return 1;
			}
		};
	}

	/**
	 * A $wpdb stub for the rotate() happy path.
	 *
	 * get_row() returns a valid, unrotated, unexpired refresh token row whose
	 * family_id matches $parent_family. The second insert() call captures the
	 * family_id that rotate() passes through into issue().
	 */
	private function make_rotate_wpdb( string $token_hash, string $parent_family, object $capture ): object {
		$future = gmdate( 'Y-m-d H:i:s', time() + 7776000 );

		return new class( $token_hash, $parent_family, $future, $capture ) {
			public string $prefix    = 'wp_';
			public int    $insert_id = 99;
			private string $token_hash;
			private string $parent_family;
			private string $future;
			private object $capture;
			private int    $get_row_calls  = 0;
			private int    $insert_calls   = 0;

			public function __construct( string $h, string $f, string $exp, object $cap ) {
				$this->token_hash    = $h;
				$this->parent_family = $f;
				$this->future        = $exp;
				$this->capture       = $cap;
			}

			public function prepare( $q, ...$a ) { return $q; }
			public function get_var( $q )         { return null; }
			public function get_results( $q )     { return array(); }
			public function query( $sql )         { return true; }

			public function get_row( $q ) {
				$this->get_row_calls++;
				if ( $this->get_row_calls === 1 ) {
					// First call from rotate(): return the old refresh token row.
					return (object) [
						'token_hash'      => $this->token_hash,
						'client_id'       => 'cl_test',
						'user_id'         => 1,
						'scope'           => 'abilities:content:read',
						'resource'        => 'https://example.com/wp-json/mcp/mcp-adapter-default-server',
						'family_id'       => $this->parent_family,
						'expires_at'      => $this->future,
						'revoked'         => 0,
						'rotated_at'      => null,
						'rotated_to_hash' => null,
					];
				}
				return null;
			}

			public function update( $table, $data, $where, $format = null, $where_format = null ) {
				return 1; // Simulate successful "mark as rotated" update.
			}

			public function insert( $table, $data, $format = null ) {
				$this->insert_calls++;
				// Second insert is the refresh token row in issue().
				if ( $this->insert_calls === 2 && isset( $data['family_id'] ) ) {
					$this->capture->family_id = $data['family_id'];
				}
				return 1;
			}
		};
	}

	/**
	 * Stub for testing the idempotent-retry path (token already rotated, within grace).
	 */
	private function make_already_rotated_wpdb( string $token_hash, string $parent_family, int $rotated_age ): object {
		$rotated_at = gmdate( 'Y-m-d H:i:s', time() - $rotated_age );
		$future     = gmdate( 'Y-m-d H:i:s', time() + 7776000 );

		return new class( $token_hash, $parent_family, $rotated_at, $future ) {
			public string $prefix    = 'wp_';
			public int    $insert_id = 99;
			private string $token_hash;
			private string $parent_family;
			private string $rotated_at;
			private string $future;
			private int    $get_row_calls = 0;

			public function __construct( string $h, string $f, string $rat, string $exp ) {
				$this->token_hash    = $h;
				$this->parent_family = $f;
				$this->rotated_at    = $rat;
				$this->future        = $exp;
			}

			public function prepare( $q, ...$a ) { return $q; }
			public function get_var( $q )         { return null; }
			public function get_results( $q )     { return array(); }
			public function query( $sql )         { return true; }

			public function get_row( $q ) {
				$this->get_row_calls++;
				if ( $this->get_row_calls === 1 ) {
					return (object) [
						'token_hash'      => $this->token_hash,
						'client_id'       => 'cl_test',
						'user_id'         => 1,
						'scope'           => 'abilities:content:read',
						'resource'        => 'https://example.com/wp-json/mcp/mcp-adapter-default-server',
						'family_id'       => $this->parent_family,
						'expires_at'      => $this->future,
						'revoked'         => 1,
						'rotated_at'      => $this->rotated_at,
						'rotated_to_hash' => hash( 'sha256', 'some-new-token' ),
					];
				}
				// Second get_row: look up the access token by rotated_to_hash (grace path).
				return (object) [
					'token_hash' => hash( 'sha256', 'some-new-token' ),
					'client_id'  => 'cl_test',
					'revoked'    => 0,
					'expires_at' => $this->future,
				];
			}

			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null ) { return 1; }
		};
	}

	/**
	 * Stub for testing replay detection (token already rotated, outside grace).
	 * Captures the family_id passed to the UPDATE that marks the family revoked.
	 */
	private function make_replay_wpdb( string $token_hash, string $parent_family, int $rotated_age, ?string &$revoked_family_out ): object {
		$rotated_at = gmdate( 'Y-m-d H:i:s', time() - $rotated_age );
		$future     = gmdate( 'Y-m-d H:i:s', time() + 7776000 );
		$cap        = new \stdClass();
		$cap->family_id = null;

		return new class( $token_hash, $parent_family, $rotated_at, $future ) {
			public string $prefix    = 'wp_';
			public int    $insert_id = 99;
			private string $token_hash;
			private string $parent_family;
			private string $rotated_at;
			private string $future;

			public function __construct( string $h, string $f, string $rat, string $exp ) {
				$this->token_hash    = $h;
				$this->parent_family = $f;
				$this->rotated_at    = $rat;
				$this->future        = $exp;
			}

			public function prepare( $q, ...$a ) { return $q; }
			public function get_var( $q )         { return null; }
			public function get_results( $q )     { return array(); }
			public function query( $sql )         { return true; }

			public function get_row( $q ) {
				return (object) [
					'token_hash'      => $this->token_hash,
					'client_id'       => 'cl_test',
					'user_id'         => 1,
					'scope'           => 'abilities:content:read',
					'resource'        => 'https://example.com/wp-json/mcp/mcp-adapter-default-server',
					'family_id'       => $this->parent_family,
					'expires_at'      => $this->future,
					'revoked'         => 1,
					'rotated_at'      => $this->rotated_at,
					'rotated_to_hash' => hash( 'sha256', 'some-new-token' ),
				];
			}

			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null ) { return 1; }
		};
	}
}
