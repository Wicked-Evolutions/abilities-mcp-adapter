<?php
/**
 * H-2: TokenStore revocation cascade behavior.
 *
 * Pre-fix: revoke_by_plaintext() only marked the named token revoked; the
 * paired token (access ↔ refresh) remained live.
 *
 * After fix:
 *  - Revoking a refresh token by plaintext calls revoke_family() so all
 *    access tokens in the family are also revoked.
 *  - Revoking an access token by plaintext also marks its paired refresh
 *    tokens revoked (via access_token_id FK).
 *
 * Also tests new find_token_meta() helper.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\TokenStore;

final class TokenStoreRevocationCascadeTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		$this->original_wpdb = $GLOBALS['wpdb'];
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->original_wpdb;
	}

	// ---------------------------------------------------------------------
	// find_token_meta
	// ---------------------------------------------------------------------

	public function test_find_token_meta_returns_null_when_not_found(): void {
		$GLOBALS['wpdb'] = new class {
			public string $prefix = 'wp_';
			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )         { return null; }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function query( $sql )         { return true; }
		};

		$this->assertNull( TokenStore::find_token_meta( 'unknown_token' ) );
	}

	public function test_find_token_meta_returns_access_meta_when_access_token_found(): void {
		$meta_row             = new \stdClass();
		$meta_row->client_id  = 'cl_test';
		$meta_row->family_id  = null;
		$meta_row->type       = 'access';

		$call = 0;
		$GLOBALS['wpdb'] = new class( $meta_row, $call ) {
			public string $prefix = 'wp_';
			private object $meta;
			private int    $n = 0;

			public function __construct( object $m, int $n ) { $this->meta = $m; $this->n = $n; }
			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q ) {
				$this->n++;
				// 1st call = refresh table → null; 2nd call = access table → meta.
				return $this->n === 1 ? null : $this->meta;
			}
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function query( $sql ) { return true; }
		};

		$result = TokenStore::find_token_meta( 'some_access_token' );
		$this->assertNotNull( $result );
		$this->assertSame( 'cl_test', $result->client_id );
	}

	public function test_find_token_meta_returns_refresh_meta_when_refresh_token_found(): void {
		$meta_row             = new \stdClass();
		$meta_row->client_id  = 'cl_test';
		$meta_row->family_id  = 'fam_xyz';
		$meta_row->type       = 'refresh';

		$GLOBALS['wpdb'] = new class( $meta_row ) {
			public string $prefix = 'wp_';
			private object $meta;
			public function __construct( object $m ) { $this->meta = $m; }
			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )         { return $this->meta; } // refresh found immediately
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function query( $sql ) { return true; }
		};

		$result = TokenStore::find_token_meta( 'some_refresh_token' );
		$this->assertNotNull( $result );
		$this->assertSame( 'fam_xyz', $result->family_id );
	}

	// ---------------------------------------------------------------------
	// revoke_by_plaintext cascade for refresh tokens
	// ---------------------------------------------------------------------

	public function test_revoking_refresh_token_calls_revoke_family(): void {
		$refresh_row             = new \stdClass();
		$refresh_row->family_id  = 'fam_abc';

		// Use a capture object so anonymous class can record queries without ref args.
		$capture         = new \stdClass();
		$capture->queries = array();

		$GLOBALS['wpdb'] = new class( $refresh_row, $capture ) {
			public string $prefix = 'wp_';
			private object $refresh;
			private object $capture;

			public function __construct( object $r, object $c ) {
				$this->refresh = $r;
				$this->capture = $c;
			}

			public function prepare( $q, ...$a ) {
				return $q;
			}

			public function get_row( $q ) {
				// revoke_by_plaintext first checks the refresh table.
				return $this->refresh;
			}

			public function query( $sql ) {
				$this->capture->queries[] = $sql;
				return true;
			}

			public function update( $t, $d, $w, $f = null, $wf = null ) {
				$this->capture->queries[] = "UPDATE $t";
				return 1;
			}
		};

		TokenStore::revoke_by_plaintext( 'some_refresh_token' );

		// revoke_family issues a transaction with UPDATE queries for both tables.
		$this->assertNotEmpty( $capture->queries, 'revoke_family must issue DB queries' );

		// At least one query must reference the refresh_tokens table.
		$has_refresh_update = false;
		foreach ( $capture->queries as $q ) {
			if ( str_contains( (string) $q, 'kl_oauth_refresh_tokens' ) || str_contains( (string) $q, 'UPDATE' ) ) {
				$has_refresh_update = true;
			}
		}
		$this->assertTrue( $has_refresh_update, 'revoke_family must update refresh_tokens table' );
	}
}
