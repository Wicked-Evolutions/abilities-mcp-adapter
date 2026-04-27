<?php
/**
 * C-2: Refresh idempotent retry returns the original plaintext pair.
 *
 * Pre-fix: TokenStore::rotate() recognised the retry-within-grace case but
 * returned a sentinel ['__idempotent_retry__' => true, ...] which TokenEndpoint
 * converted into a 400 invalid_grant. The bridge's retry-on-network-blip path
 * (the very scenario H.2.1's grace was designed for) hit that 400, marked the
 * site auth_status=expired, and evicted the operator to reauth.
 *
 * After fix (Option A — encrypt-at-rest):
 *   - On rotation, the new plaintext pair is AES-256-GCM encrypted under a key
 *     HKDF-derived from the old refresh token plaintext + AUTH_KEY. Ciphertext
 *     and IV are stored on the old refresh token row (replay_blob,
 *     replay_blob_iv columns).
 *   - On retry within ROTATION_GRACE_SECONDS, the stored blob is decrypted
 *     using the supplied old plaintext and the original pair is returned.
 *   - The blob is wiped after one successful retry (one-shot delivery). A
 *     second retry within the same grace window finds an empty blob and
 *     returns null. (Same plaintext can't be redelivered indefinitely.)
 *   - A retry outside the grace window revokes the entire family.
 *
 * Security argument:
 *   - The decryption key is bound to the old refresh token's plaintext, which
 *     is provided by the retrying client itself in the request body and never
 *     persisted server-side. A DB exfiltrator with access to the blob alone
 *     cannot decrypt it without ALSO having that plaintext.
 *   - AUTH_KEY (server-private) is mixed into HKDF salt so two installations
 *     with the same token plaintext (impossibly improbable, but theoretical)
 *     produce different keys.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\TokenStore;

final class TokenStoreReplayBlobTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		$this->original_wpdb = $GLOBALS['wpdb'];
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->original_wpdb;
	}

	// -------------------------------------------------------------------------
	// Initial rotation populates replay_blob / replay_blob_iv
	// -------------------------------------------------------------------------

	public function test_initial_rotation_writes_replay_blob_and_iv(): void {
		$family_id       = 'fam_' . bin2hex( random_bytes( 8 ) );
		$old_plaintext   = bin2hex( random_bytes( 32 ) );
		$old_hash        = hash( 'sha256', $old_plaintext );

		$updates = new \stdClass();
		$updates->captured = [];

		$GLOBALS['wpdb'] = $this->make_normal_rotate_wpdb( $old_hash, $family_id, $updates );

		$result = TokenStore::rotate( $old_plaintext, 'cl_test' );

		$this->assertNotNull( $result, 'Normal rotation must succeed' );
		$this->assertArrayHasKey( 'access_token', $result );
		$this->assertArrayHasKey( 'refresh_token', $result );
		$this->assertArrayHasKey( 'token_type', $result );
		$this->assertSame( 'Bearer', $result['token_type'] );

		// One of the captured updates is the rotation marker — it must include
		// non-empty replay_blob and replay_blob_iv.
		$rotation_update = null;
		foreach ( $updates->captured as $upd ) {
			if ( isset( $upd['rotated_to_hash'] ) ) {
				$rotation_update = $upd;
				break;
			}
		}
		$this->assertNotNull( $rotation_update, 'Rotation marker UPDATE must be issued' );
		$this->assertArrayHasKey( 'replay_blob', $rotation_update );
		$this->assertArrayHasKey( 'replay_blob_iv', $rotation_update );
		$this->assertNotEmpty( $rotation_update['replay_blob'], 'replay_blob must be non-empty ciphertext' );
		$this->assertSame( 24, strlen( $rotation_update['replay_blob_iv'] ), 'IV is 12 bytes hex-encoded → 24 chars' );
	}

	// -------------------------------------------------------------------------
	// Idempotent retry decrypts blob → returns original plaintext pair
	// -------------------------------------------------------------------------

	public function test_idempotent_retry_returns_original_plaintext_pair(): void {
		// Pre-stage: encrypt a known pair under a known plaintext, then drive
		// rotate() through the retry path with a row that already contains the
		// blob and a recent rotated_at.
		$old_plaintext = bin2hex( random_bytes( 32 ) );
		$old_hash      = hash( 'sha256', $old_plaintext );
		$family_id     = 'fam_' . bin2hex( random_bytes( 8 ) );

		$original_pair = [
			'access_token'  => 'access_' . bin2hex( random_bytes( 16 ) ),
			'token_type'    => 'Bearer',
			'refresh_token' => 'refresh_' . bin2hex( random_bytes( 16 ) ),
			'expires_in'    => 86400,
			'scope'         => 'abilities:content:read',
		];
		$blob = $this->encrypt_pair( $original_pair, $old_plaintext );

		$GLOBALS['wpdb'] = $this->make_grace_retry_wpdb( $old_hash, $family_id, $blob, rotated_age: 5 );

		$result = TokenStore::rotate( $old_plaintext, 'cl_test' );

		$this->assertNotNull( $result, 'Retry within grace must succeed' );
		$this->assertSame( $original_pair['access_token'], $result['access_token'], 'Original access_token returned verbatim' );
		$this->assertSame( $original_pair['refresh_token'], $result['refresh_token'], 'Original refresh_token returned verbatim' );
		$this->assertSame( 'Bearer', $result['token_type'] );
		$this->assertSame( 86400, $result['expires_in'] );
		$this->assertSame( 'abilities:content:read', $result['scope'] );
	}

	public function test_idempotent_retry_wipes_blob_after_delivery(): void {
		$old_plaintext = bin2hex( random_bytes( 32 ) );
		$old_hash      = hash( 'sha256', $old_plaintext );
		$family_id     = 'fam_' . bin2hex( random_bytes( 8 ) );
		$pair          = [
			'access_token'  => 'a',
			'token_type'    => 'Bearer',
			'refresh_token' => 'r',
			'expires_in'    => 86400,
			'scope'         => 's',
		];
		$blob = $this->encrypt_pair( $pair, $old_plaintext );

		$updates = new \stdClass();
		$updates->captured = [];

		$GLOBALS['wpdb'] = $this->make_grace_retry_wpdb( $old_hash, $family_id, $blob, rotated_age: 5, updates: $updates );

		TokenStore::rotate( $old_plaintext, 'cl_test' );

		// One update must NULL both blob columns.
		$found_wipe = false;
		foreach ( $updates->captured as $upd ) {
			if ( array_key_exists( 'replay_blob', $upd ) && array_key_exists( 'replay_blob_iv', $upd ) && $upd['replay_blob'] === null ) {
				$found_wipe = true;
				break;
			}
		}
		$this->assertTrue( $found_wipe, 'Blob columns must be NULL-ed after one-shot delivery' );
	}

	// -------------------------------------------------------------------------
	// Retry without blob → null (no panic, no fresh family revocation either)
	// -------------------------------------------------------------------------

	public function test_grace_retry_without_blob_returns_null(): void {
		$old_plaintext = bin2hex( random_bytes( 32 ) );
		$old_hash      = hash( 'sha256', $old_plaintext );
		$family_id     = 'fam_legacy';

		$GLOBALS['wpdb'] = $this->make_grace_retry_wpdb( $old_hash, $family_id, blob: null, rotated_age: 5 );

		$this->assertNull( TokenStore::rotate( $old_plaintext, 'cl_test' ) );
	}

	// -------------------------------------------------------------------------
	// Replay outside grace → null + family revoke (existing behaviour, unchanged)
	// -------------------------------------------------------------------------

	public function test_replay_outside_grace_revokes_family(): void {
		$old_plaintext = bin2hex( random_bytes( 32 ) );
		$old_hash      = hash( 'sha256', $old_plaintext );
		$family_id     = 'fam_replay';

		$queries = new \stdClass();
		$queries->captured = [];

		$GLOBALS['wpdb'] = $this->make_grace_retry_wpdb(
			$old_hash,
			$family_id,
			blob: $this->encrypt_pair(
				[ 'access_token' => 'x', 'token_type' => 'Bearer', 'refresh_token' => 'y', 'expires_in' => 1, 'scope' => '' ],
				$old_plaintext
			),
			rotated_age: 60, // Outside 30s grace.
			query_capture: $queries
		);

		$this->assertNull( TokenStore::rotate( $old_plaintext, 'cl_test' ) );

		$family_revoke_seen = false;
		foreach ( $queries->captured as $q ) {
			if ( str_contains( $q, 'family_id' ) && stripos( $q, 'UPDATE' ) !== false ) {
				$family_revoke_seen = true;
				break;
			}
		}
		$this->assertTrue( $family_revoke_seen, 'Replay outside grace must trigger family-revoke UPDATE' );
	}

	// -------------------------------------------------------------------------
	// Wrong plaintext (key mismatch) → null
	// -------------------------------------------------------------------------

	public function test_grace_retry_with_wrong_plaintext_returns_null(): void {
		$correct_plaintext = bin2hex( random_bytes( 32 ) );
		$wrong_plaintext   = bin2hex( random_bytes( 32 ) );
		// The DB lookup is by token_hash of the plaintext supplied to rotate(),
		// so to exercise "row-found-but-decrypt-fails" we craft a row whose
		// hash matches the wrong plaintext, but whose blob was encrypted under
		// the correct one.
		$wrong_hash = hash( 'sha256', $wrong_plaintext );

		$pair = [ 'access_token' => 'a', 'token_type' => 'Bearer', 'refresh_token' => 'r', 'expires_in' => 1, 'scope' => '' ];
		$blob = $this->encrypt_pair( $pair, $correct_plaintext );

		$GLOBALS['wpdb'] = $this->make_grace_retry_wpdb( $wrong_hash, 'fam_x', $blob, rotated_age: 5 );

		$this->assertNull( TokenStore::rotate( $wrong_plaintext, 'cl_test' ) );
	}

	// -------------------------------------------------------------------------
	// Tampered ciphertext → null (GCM tag verification)
	// -------------------------------------------------------------------------

	public function test_tampered_ciphertext_fails_decryption(): void {
		$old_plaintext = bin2hex( random_bytes( 32 ) );
		$old_hash      = hash( 'sha256', $old_plaintext );

		$pair = [ 'access_token' => 'a', 'token_type' => 'Bearer', 'refresh_token' => 'r', 'expires_in' => 1, 'scope' => '' ];
		$blob = $this->encrypt_pair( $pair, $old_plaintext );
		// Flip a byte in the middle of the ciphertext (not in the auth tag).
		$blob['ciphertext'][5] = chr( ord( $blob['ciphertext'][5] ) ^ 0x01 );

		$GLOBALS['wpdb'] = $this->make_grace_retry_wpdb( $old_hash, 'fam_t', $blob, rotated_age: 5 );

		$this->assertNull( TokenStore::rotate( $old_plaintext, 'cl_test' ) );
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Encrypt a token pair the same way TokenStore does internally, so the
	 * test can pre-populate a row with a valid blob.
	 */
	private function encrypt_pair( array $pair, string $old_refresh_plaintext ): array {
		$salt = defined( 'AUTH_KEY' ) ? (string) AUTH_KEY : '';
		$key  = hash_hkdf( 'sha256', $old_refresh_plaintext, 32, 'oauth-replay-blob', $salt );
		$iv   = random_bytes( 12 );
		$tag  = '';
		$pt   = json_encode( [
			'access_token'  => $pair['access_token'],
			'token_type'    => $pair['token_type'],
			'refresh_token' => $pair['refresh_token'],
			'expires_in'    => $pair['expires_in'],
			'scope'         => $pair['scope'],
		] );
		$ct   = openssl_encrypt( $pt, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
		return [
			'ciphertext' => $ct . $tag,
			'iv'         => bin2hex( $iv ),
		];
	}

	/**
	 * $wpdb stub for the normal rotation path (token not yet rotated, still valid).
	 * Captures every update() call so the test can assert the rotation marker
	 * includes replay_blob / replay_blob_iv.
	 */
	private function make_normal_rotate_wpdb( string $old_hash, string $family_id, object $updates ): object {
		$future = gmdate( 'Y-m-d H:i:s', time() + 7776000 );

		return new class( $old_hash, $family_id, $future, $updates ) {
			public string $prefix    = 'wp_';
			public int    $insert_id = 99;
			private string $old_hash;
			private string $family_id;
			private string $future;
			private object $updates;
			private int    $get_row_calls = 0;

			public function __construct( string $h, string $f, string $exp, object $u ) {
				$this->old_hash  = $h;
				$this->family_id = $f;
				$this->future    = $exp;
				$this->updates   = $u;
			}

			public function prepare( $q, ...$a ) { return $q; }
			public function get_var( $q )         { return null; }
			public function get_results( $q )     { return array(); }
			public function query( $sql )         { return true; }

			public function get_row( $q ) {
				$this->get_row_calls++;
				if ( $this->get_row_calls === 1 ) {
					return (object) [
						'token_hash'      => $this->old_hash,
						'client_id'       => 'cl_test',
						'user_id'         => 1,
						'scope'           => 'abilities:content:read',
						'resource'        => 'https://example.com/wp-json/mcp/mcp-adapter-default-server',
						'family_id'       => $this->family_id,
						'expires_at'      => $this->future,
						'revoked'         => 0,
						'rotated_at'      => null,
						'rotated_to_hash' => null,
						'replay_blob'     => null,
						'replay_blob_iv'  => null,
					];
				}
				return null;
			}

			public function update( $table, $data, $where, $format = null, $where_format = null ) {
				$this->updates->captured[] = $data;
				return 1;
			}

			public function insert( $t, $d, $f = null ) { return 1; }
		};
	}

	/**
	 * $wpdb stub for the retry-within-grace path. Returns a row whose
	 * rotated_at is $rotated_age seconds ago, with $blob populated.
	 *
	 * @param array<string,string>|null $blob   ['ciphertext' => ..., 'iv' => ...] or null
	 * @param object|null               $updates Capture for update() calls
	 * @param object|null               $query_capture Capture for query() calls
	 */
	private function make_grace_retry_wpdb(
		string $old_hash,
		string $family_id,
		?array $blob,
		int    $rotated_age,
		?object $updates       = null,
		?object $query_capture = null
	): object {
		$rotated_at = gmdate( 'Y-m-d H:i:s', time() - $rotated_age );
		$future     = gmdate( 'Y-m-d H:i:s', time() + 7776000 );

		return new class( $old_hash, $family_id, $rotated_at, $future, $blob, $updates, $query_capture ) {
			public string $prefix    = 'wp_';
			public int    $insert_id = 99;
			private string $old_hash;
			private string $family_id;
			private string $rotated_at;
			private string $future;
			private ?array $blob;
			private ?object $updates;
			private ?object $query_capture;

			public function __construct( string $h, string $f, string $rat, string $exp, ?array $b, ?object $u, ?object $qc ) {
				$this->old_hash      = $h;
				$this->family_id     = $f;
				$this->rotated_at    = $rat;
				$this->future        = $exp;
				$this->blob          = $b;
				$this->updates       = $u;
				$this->query_capture = $qc;
			}

			public function prepare( $q, ...$a ) { return $q; }
			public function get_var( $q )         { return null; }
			public function get_results( $q )     { return array(); }

			public function query( $sql ) {
				if ( $this->query_capture ) {
					$this->query_capture->captured[] = $sql;
				}
				return 1;
			}

			public function get_row( $q ) {
				return (object) [
					'token_hash'      => $this->old_hash,
					'client_id'       => 'cl_test',
					'user_id'         => 1,
					'scope'           => 'abilities:content:read',
					'resource'        => 'https://example.com/wp-json/mcp/mcp-adapter-default-server',
					'family_id'       => $this->family_id,
					'expires_at'      => $this->future,
					'revoked'         => 1,
					'rotated_at'      => $this->rotated_at,
					'rotated_to_hash' => 'newhash',
					'replay_blob'     => $this->blob['ciphertext'] ?? null,
					'replay_blob_iv'  => $this->blob['iv'] ?? null,
				];
			}

			public function update( $table, $data, $where, $format = null, $where_format = null ) {
				if ( $this->updates ) {
					$this->updates->captured[] = $data;
				}
				return 1;
			}

			public function insert( $t, $d, $f = null ) { return 1; }
		};
	}
}
