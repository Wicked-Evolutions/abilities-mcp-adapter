<?php
/**
 * #88: TokenStore persists / inherits selected_role.
 *
 * Pins:
 *   - TokenStore::issue() writes the supplied selected_role onto BOTH the
 *     access-token row and the paired refresh-token row.
 *   - TokenStore::issue() defaults to '' when no role is supplied.
 *   - TokenStore::rotate() reads selected_role from the old refresh row and
 *     plumbs it into the new pair via issue(). This is the property that
 *     guarantees an operator's deliberate role downgrade survives token
 *     rotation — the v1.4.5 release-gate behavior named in §4 B.2.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\TokenStore;

final class TokenStoreSelectedRoleTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		$this->original_wpdb = $GLOBALS['wpdb'];
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->original_wpdb;
	}

	// -------------------------------------------------------------------------
	// issue() — selected_role lands on access + refresh rows
	// -------------------------------------------------------------------------

	public function test_issue_persists_selected_role_on_both_rows(): void {
		$inserts = array();
		$GLOBALS['wpdb'] = new class( $inserts ) {
			public string $prefix    = 'wp_';
			public int    $insert_id = 99;
			public function __construct( public array &$inserts ) {}
			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )         { return null; }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null ) {
				$this->inserts[] = array( 'table' => (string) $t, 'data' => $d );
				return 1;
			}
			public function query( $sql )         { return true; }
		};

		TokenStore::issue(
			'client-x',
			7,
			'abilities:content:read',
			'https://example.com/wp-json/mcp/x',
			TokenStore::ACCESS_TTL,
			TokenStore::REFRESH_TTL,
			null,
			'editor'
		);

		$this->assertCount( 2, $GLOBALS['wpdb']->inserts, 'Both access + refresh rows must be written.' );
		foreach ( $GLOBALS['wpdb']->inserts as $row ) {
			$this->assertArrayHasKey( 'selected_role', $row['data'] );
			$this->assertSame( 'editor', $row['data']['selected_role'] );
		}
	}

	public function test_issue_defaults_selected_role_to_empty_string(): void {
		$inserts = array();
		$GLOBALS['wpdb'] = new class( $inserts ) {
			public string $prefix    = 'wp_';
			public int    $insert_id = 99;
			public function __construct( public array &$inserts ) {}
			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )         { return null; }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null ) {
				$this->inserts[] = array( 'table' => (string) $t, 'data' => $d );
				return 1;
			}
			public function query( $sql )         { return true; }
		};

		// No selected_role argument — default '' (auto-approve / single-role path).
		TokenStore::issue(
			'client-x',
			7,
			'abilities:content:read',
			'https://example.com/wp-json/mcp/x'
		);

		foreach ( $GLOBALS['wpdb']->inserts as $row ) {
			$this->assertSame( '', $row['data']['selected_role'] );
		}
	}

	// -------------------------------------------------------------------------
	// rotate() — selected_role inherited from old refresh row to new pair
	// -------------------------------------------------------------------------

	public function test_rotate_inherits_selected_role_from_old_refresh_row(): void {
		// Stage: an existing refresh token row with selected_role='editor'.
		// rotate() must call issue() with that role so the new pair carries it.
		$old_refresh_plaintext = bin2hex( random_bytes( 32 ) );
		$old_refresh_hash      = hash( 'sha256', $old_refresh_plaintext );

		$captured_inserts = array();
		$GLOBALS['wpdb'] = new class( $old_refresh_hash, $captured_inserts ) {
			public string $prefix    = 'wp_';
			public int    $insert_id = 100;

			public function __construct(
				public string $old_refresh_hash,
				public array &$captured_inserts
			) {}

			public function prepare( $q, ...$a ) { return $q; }

			public function get_row( $q ) {
				// Return a minimal refresh row with selected_role='editor'.
				$row                  = new \stdClass();
				$row->id              = 1;
				$row->token_hash      = $this->old_refresh_hash;
				$row->access_token_id = 50;
				$row->client_id       = 'client-x';
				$row->user_id         = 7;
				$row->scope           = 'abilities:content:read';
				$row->resource        = 'https://example.com/wp-json/mcp/x';
				$row->family_id       = 'fam-abc';
				$row->selected_role   = 'editor';
				// Far future: not expired.
				$row->expires_at      = gmdate( 'Y-m-d H:i:s', time() + 86400 );
				$row->revoked         = 0;
				$row->rotated_at      = null;
				$row->rotated_to_hash = null;
				$row->replay_blob     = null;
				$row->replay_blob_iv  = null;
				return $row;
			}

			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null ) {
				// Capture rows issued by the new-pair side of rotate().
				$this->captured_inserts[] = array( 'table' => (string) $t, 'data' => $d );
				return 1;
			}
			public function query( $sql ) { return true; }
		};

		$result = TokenStore::rotate( $old_refresh_plaintext, 'client-x' );

		$this->assertNotNull( $result, 'rotate() must succeed for a fresh, valid refresh row.' );
		$this->assertCount( 2, $GLOBALS['wpdb']->captured_inserts, 'New access + refresh rows must be written.' );
		foreach ( $GLOBALS['wpdb']->captured_inserts as $row ) {
			$this->assertArrayHasKey( 'selected_role', $row['data'] );
			$this->assertSame(
				'editor',
				$row['data']['selected_role'],
				'Rotation must inherit selected_role from the old refresh row.'
			);
		}
	}

	public function test_rotate_inherits_empty_selected_role_when_old_row_had_none(): void {
		// Pre-fix tokens (issued before db_version 1.2.0) and tokens issued via
		// auto-approve both have selected_role=''. Rotation must preserve ''.
		$old_refresh_plaintext = bin2hex( random_bytes( 32 ) );
		$old_refresh_hash      = hash( 'sha256', $old_refresh_plaintext );

		$captured_inserts = array();
		$GLOBALS['wpdb'] = new class( $old_refresh_hash, $captured_inserts ) {
			public string $prefix    = 'wp_';
			public int    $insert_id = 100;

			public function __construct(
				public string $old_refresh_hash,
				public array &$captured_inserts
			) {}

			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q ) {
				$row                  = new \stdClass();
				$row->id              = 1;
				$row->token_hash      = $this->old_refresh_hash;
				$row->access_token_id = 50;
				$row->client_id       = 'client-x';
				$row->user_id         = 7;
				$row->scope           = 'abilities:content:read';
				$row->resource        = 'https://example.com/wp-json/mcp/x';
				$row->family_id       = 'fam-abc';
				$row->selected_role   = '';
				$row->expires_at      = gmdate( 'Y-m-d H:i:s', time() + 86400 );
				$row->revoked         = 0;
				$row->rotated_at      = null;
				$row->rotated_to_hash = null;
				$row->replay_blob     = null;
				$row->replay_blob_iv  = null;
				return $row;
			}
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null ) {
				$this->captured_inserts[] = array( 'table' => (string) $t, 'data' => $d );
				return 1;
			}
			public function query( $sql ) { return true; }
		};

		TokenStore::rotate( $old_refresh_plaintext, 'client-x' );

		foreach ( $GLOBALS['wpdb']->captured_inserts as $row ) {
			$this->assertSame( '', $row['data']['selected_role'] );
		}
	}

	public function test_rotate_handles_old_row_missing_selected_role_property(): void {
		// Defensive: a refresh row read from a pre-migration table won't have a
		// selected_role property at all. Rotation must default to '' rather
		// than throwing on the missing property.
		$old_refresh_plaintext = bin2hex( random_bytes( 32 ) );
		$old_refresh_hash      = hash( 'sha256', $old_refresh_plaintext );

		$captured_inserts = array();
		$GLOBALS['wpdb'] = new class( $old_refresh_hash, $captured_inserts ) {
			public string $prefix    = 'wp_';
			public int    $insert_id = 100;

			public function __construct(
				public string $old_refresh_hash,
				public array &$captured_inserts
			) {}

			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q ) {
				$row                  = new \stdClass();
				$row->id              = 1;
				$row->token_hash      = $this->old_refresh_hash;
				$row->access_token_id = 50;
				$row->client_id       = 'client-x';
				$row->user_id         = 7;
				$row->scope           = 'abilities:content:read';
				$row->resource        = 'https://example.com/wp-json/mcp/x';
				$row->family_id       = 'fam-abc';
				// no selected_role property
				$row->expires_at      = gmdate( 'Y-m-d H:i:s', time() + 86400 );
				$row->revoked         = 0;
				$row->rotated_at      = null;
				$row->rotated_to_hash = null;
				$row->replay_blob     = null;
				$row->replay_blob_iv  = null;
				return $row;
			}
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null ) {
				$this->captured_inserts[] = array( 'table' => (string) $t, 'data' => $d );
				return 1;
			}
			public function query( $sql ) { return true; }
		};

		$result = TokenStore::rotate( $old_refresh_plaintext, 'client-x' );

		$this->assertNotNull( $result );
		foreach ( $GLOBALS['wpdb']->captured_inserts as $row ) {
			$this->assertSame( '', $row['data']['selected_role'] );
		}
	}
}
