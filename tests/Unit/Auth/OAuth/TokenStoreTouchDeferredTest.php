<?php
/**
 * L-2: TokenStore::touch deferred-write semantics.
 *
 * Audit (2026-04-27) flagged the synchronous `UPDATE wp_kl_oauth_tokens
 * SET last_used_at = ... WHERE token_hash = ?` on every authenticated MCP
 * request as a hot row under burst load. This test pins the post-fix
 * contract:
 *   - `touch()` does not issue a DB write itself.
 *   - Multiple `touch()` calls for the same token within one request
 *     coalesce into a single UPDATE on flush.
 *   - Distinct token_hashes flush as N UPDATEs.
 *   - Empty buffer flush is a no-op.
 *   - Empty token_hash is a no-op.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\TokenStore;

final class TokenStoreTouchDeferredTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		$this->original_wpdb = $GLOBALS['wpdb'];
		$this->install_capturing_wpdb();
		TokenStore::reset_pending_touches_for_tests();
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->original_wpdb;
		TokenStore::reset_pending_touches_for_tests();
	}

	/**
	 * $wpdb stub that records every update() call so tests can assert on the
	 * exact (table, data, where) arguments passed.
	 */
	private function install_capturing_wpdb(): void {
		$GLOBALS['wpdb'] = new class {
			public string $prefix = 'wp_';
			/** @var array<int, array{table:string, data:array, where:array}> */
			public array $update_calls = array();

			public function prepare( $q, ...$a ) { return $q; }
			public function get_row( $q )         { return null; }
			public function get_var( $q )         { return null; }
			public function get_results( $q )     { return array(); }
			public function insert( $t, $d, $f = null ) { return 1; }
			public function query( $sql )         { return true; }

			public function update( $table, $data, $where, $format = null, $where_format = null ) {
				$this->update_calls[] = array(
					'table' => (string) $table,
					'data'  => (array) $data,
					'where' => (array) $where,
				);
				return 1;
			}
		};
	}

	// ─── touch() does not write synchronously ───────────────────────────────────

	public function test_touch_does_not_issue_immediate_db_write(): void {
		TokenStore::touch( 'hash-a' );

		$this->assertSame( array(), $GLOBALS['wpdb']->update_calls,
			'touch() must defer the wpdb->update; no write before shutdown flush'
		);
	}

	// ─── flush coalesces same-token touches ─────────────────────────────────────

	public function test_repeat_touch_for_same_token_flushes_one_update(): void {
		TokenStore::touch( 'hash-a' );
		TokenStore::touch( 'hash-a' );
		TokenStore::touch( 'hash-a' );

		TokenStore::flush_pending_touches();

		$this->assertCount( 1, $GLOBALS['wpdb']->update_calls,
			'Three touches for the same token must coalesce into one UPDATE'
		);
		$call = $GLOBALS['wpdb']->update_calls[0];
		$this->assertSame( 'hash-a', $call['where']['token_hash'] );
		$this->assertArrayHasKey( 'last_used_at', $call['data'] );
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
			(string) $call['data']['last_used_at']
		);
	}

	// ─── flush issues one update per distinct token ─────────────────────────────

	public function test_touches_for_distinct_tokens_flush_separately(): void {
		TokenStore::touch( 'hash-a' );
		TokenStore::touch( 'hash-b' );
		TokenStore::touch( 'hash-c' );

		TokenStore::flush_pending_touches();

		$this->assertCount( 3, $GLOBALS['wpdb']->update_calls );

		$hashes = array_map(
			static fn( $c ) => $c['where']['token_hash'],
			$GLOBALS['wpdb']->update_calls
		);
		sort( $hashes );
		$this->assertSame( array( 'hash-a', 'hash-b', 'hash-c' ), $hashes );
	}

	// ─── flush is idempotent / clears the buffer ────────────────────────────────

	public function test_flush_is_idempotent_after_buffer_drained(): void {
		TokenStore::touch( 'hash-a' );
		TokenStore::flush_pending_touches();
		TokenStore::flush_pending_touches();

		$this->assertCount( 1, $GLOBALS['wpdb']->update_calls,
			'A second flush with an empty buffer must be a no-op'
		);
	}

	public function test_flush_with_empty_buffer_is_noop(): void {
		TokenStore::flush_pending_touches();

		$this->assertSame( array(), $GLOBALS['wpdb']->update_calls );
	}

	// ─── empty token_hash guard ─────────────────────────────────────────────────

	public function test_empty_token_hash_is_noop(): void {
		TokenStore::touch( '' );
		TokenStore::flush_pending_touches();

		$this->assertSame( array(), $GLOBALS['wpdb']->update_calls,
			'touch("") must not enqueue a write'
		);
	}

	// ─── post-flush touches re-buffer correctly (sequential FPM-style use) ──────

	public function test_touch_after_flush_buffers_the_next_request_window(): void {
		// First "request": one touch then flush.
		TokenStore::touch( 'hash-a' );
		TokenStore::flush_pending_touches();

		// Second "request" within the same process: another touch then flush.
		// Even though the shutdown flag stays sticky in this single PHP process
		// (PHPUnit doesn't reset statics between tests), the buffer must still
		// accept new entries and the next flush must drain them.
		TokenStore::touch( 'hash-a' );
		TokenStore::flush_pending_touches();

		$this->assertCount( 2, $GLOBALS['wpdb']->update_calls,
			'Subsequent touch+flush cycles must continue to write'
		);
	}
}
