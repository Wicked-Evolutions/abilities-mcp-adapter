<?php
/**
 * Tests for AuthorizationCodeStore pure-logic methods.
 *
 * DB-dependent methods (store, consume) require integration setup.
 * compute_challenge() is pure and fully unit-testable.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationCodeStore;

final class AuthorizationCodeStoreTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		$this->original_wpdb                = $GLOBALS['wpdb'];
		$GLOBALS['wp_test_actions_invoked'] = array();
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb']                    = $this->original_wpdb;
		$GLOBALS['wp_test_actions_invoked'] = array();
	}

	// --- PKCE S256 challenge computation (H.1.1) ---

	public function test_compute_challenge_matches_rfc7636_s256(): void {
		// RFC 7636 test vector.
		$verifier  = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
		$expected  = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
		$challenge = AuthorizationCodeStore::compute_challenge( $verifier );

		$this->assertSame( $expected, $challenge );
	}

	public function test_compute_challenge_different_verifiers_produce_different_challenges(): void {
		$c1 = AuthorizationCodeStore::compute_challenge( 'verifier_one_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' );
		$c2 = AuthorizationCodeStore::compute_challenge( 'verifier_two_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' );

		$this->assertNotSame( $c1, $c2 );
	}

	public function test_compute_challenge_is_base64url_without_padding(): void {
		$verifier  = str_repeat( 'a', 43 ); // minimum allowed length per RFC 7636.
		$challenge = AuthorizationCodeStore::compute_challenge( $verifier );

		// Must not contain '+', '/', or '=' (base64url, no padding).
		$this->assertStringNotContainsString( '+', $challenge );
		$this->assertStringNotContainsString( '/', $challenge );
		$this->assertStringNotContainsString( '=', $challenge );
	}

	// --- M-9: store() return contract + boundary log on insert failure ---

	public function test_store_returns_true_on_successful_insert(): void {
		$GLOBALS['wpdb'] = new class {
			public string $prefix     = 'wp_';
			public string $last_error = '';
			public function insert( $t, $d, $f = null ) { return 1; }
		};

		$result = AuthorizationCodeStore::store(
			str_repeat( 'a', 64 ), 'client-x', 1, 'https://example.com/cb',
			'abilities:content:read', 'https://example.com/wp-json/mcp/abilities-mcp-adapter-default-server',
			str_repeat( 'b', 43 )
		);

		$this->assertTrue( $result );
	}

	public function test_store_returns_false_when_wpdb_insert_returns_false(): void {
		$GLOBALS['wpdb'] = new class {
			public string $prefix     = 'wp_';
			public string $last_error = "Duplicate entry 'aa..' for key 'code_hash'";
			public function insert( $t, $d, $f = null ) { return false; }
		};

		$result = AuthorizationCodeStore::store(
			str_repeat( 'a', 64 ), 'client-x', 1, 'https://example.com/cb',
			'abilities:content:read', 'https://example.com/wp-json/mcp/abilities-mcp-adapter-default-server',
			str_repeat( 'b', 43 )
		);

		$this->assertFalse( $result );
	}

	public function test_store_emits_boundary_event_with_client_id_and_wpdb_error_on_failure(): void {
		$GLOBALS['wpdb'] = new class {
			public string $prefix     = 'wp_';
			public string $last_error = "Duplicate entry 'aa..' for key 'code_hash'";
			public function insert( $t, $d, $f = null ) { return false; }
		};

		AuthorizationCodeStore::store(
			str_repeat( 'a', 64 ), 'client-x', 1, 'https://example.com/cb',
			'abilities:content:read', 'https://example.com/wp-json/mcp/abilities-mcp-adapter-default-server',
			str_repeat( 'b', 43 )
		);

		$matched = null;
		foreach ( $GLOBALS['wp_test_actions_invoked'] as $entry ) {
			if (
				$entry['hook'] === 'mcp_adapter_boundary_event'
				&& isset( $entry['args'][0] )
				&& $entry['args'][0] === 'boundary.oauth_code_insert_failed'
			) {
				$matched = $entry;
				break;
			}
		}

		$this->assertNotNull( $matched, 'Insert failure must emit boundary.oauth_code_insert_failed' );

		$tags = $matched['args'][1] ?? array();
		$this->assertSame( 'client-x', $tags['client_id'] ?? null );
		$this->assertStringContainsString( 'code_hash', (string) ( $tags['wpdb_error'] ?? '' ) );
	}

	public function test_store_does_not_emit_boundary_event_on_success(): void {
		$GLOBALS['wpdb'] = new class {
			public string $prefix     = 'wp_';
			public string $last_error = '';
			public function insert( $t, $d, $f = null ) { return 1; }
		};

		AuthorizationCodeStore::store(
			str_repeat( 'a', 64 ), 'client-x', 1, 'https://example.com/cb',
			'abilities:content:read', 'https://example.com/wp-json/mcp/abilities-mcp-adapter-default-server',
			str_repeat( 'b', 43 )
		);

		foreach ( $GLOBALS['wp_test_actions_invoked'] as $entry ) {
			if (
				$entry['hook'] === 'mcp_adapter_boundary_event'
				&& isset( $entry['args'][0] )
				&& $entry['args'][0] === 'boundary.oauth_code_insert_failed'
			) {
				$this->fail( 'Successful insert must not emit boundary.oauth_code_insert_failed' );
			}
		}
		$this->assertTrue( true ); // No event found — pass.
	}
}
