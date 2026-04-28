<?php
/**
 * L-1: Bearer token must be trim()ed after extraction.
 *
 * Pre-fix: $bearer_token = substr( $auth_header, 7 ); — a header like
 * "Authorization: Bearer  TOKEN" (two spaces) becomes " TOKEN", hashed as
 * " TOKEN", which never matches a stored token. A misbehaving proxy that
 * adds whitespace silently breaks auth and the operator sees invalid_token
 * with no obvious cause.
 *
 * After fix: $bearer_token = trim( substr( $auth_header, 7 ) ); — leading,
 * trailing, and tab whitespace is stripped before hashing.
 *
 * Drives AuthorizationServer::authenticate_bearer() with a header that has
 * extra whitespace, and asserts the bound user_id is returned (i.e. the
 * trimmed token hashed correctly).
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationServer;
use WickedEvolutions\McpAdapter\Auth\OAuth\OAuthRequestContext;

if ( ! defined( 'REST_REQUEST' ) ) {
	define( 'REST_REQUEST', true );
}

final class BearerHeaderTrimTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		parent::setUp();
		$this->original_wpdb = $GLOBALS['wpdb'];
		OAuthRequestContext::reset();
		// Target the MCP resource so authenticate_bearer doesn't no-op via C-1.
		$_SERVER['REQUEST_URI'] = '/wp-json/mcp/mcp-adapter-default-server';
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->original_wpdb;
		unset( $_SERVER['REQUEST_URI'], $_SERVER['HTTP_AUTHORIZATION'] );
		OAuthRequestContext::reset();
		parent::tearDown();
	}

	/**
	 * Build a $wpdb stub that returns a valid token row only when the
	 * lookup hash matches the canonical (un-padded) token. Used to assert
	 * that authenticate_bearer hashed the trimmed value.
	 */
	private function install_token_row_for_canonical( string $canonical_plaintext, int $user_id ): void {
		$canonical_hash = hash( 'sha256', $canonical_plaintext );
		$expires_at     = ( new \DateTimeImmutable( '+1 hour', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s' );

		$GLOBALS['wpdb'] = new class( $canonical_hash, $user_id, $expires_at ) {
			public string $prefix = 'wp_';
			private string $expected_hash;
			private int    $user_id;
			private string $expires_at;

			public function __construct( string $h, int $uid, string $exp ) {
				$this->expected_hash = $h;
				$this->user_id       = $uid;
				$this->expires_at    = $exp;
			}

			public function prepare( $q, ...$a ) {
				// $a[0] is the hash bound by TokenStore::lookup_access_token.
				$this->captured_hash = $a[0] ?? '';
				return $q;
			}

			public string $captured_hash = '';

			public function get_row( $q ) {
				if ( $this->captured_hash !== $this->expected_hash ) {
					return null;
				}
				$row = new \stdClass();
				$row->id          = 7;
				$row->user_id     = $this->user_id;
				$row->client_id   = 'cl_test';
				$row->scope       = 'abilities:content:read';
				$row->resource    = 'https://example.com/wp-json/mcp/mcp-adapter-default-server';
				$row->token_hash  = $this->expected_hash;
				$row->expires_at  = $this->expires_at;
				$row->revoked     = 0;
				return $row;
			}

			public function get_results( $q ) { return array(); }
			public function get_var( $q )     { return null; }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null )                  { return 1; }
			public function query( $sql )                                 { return true; }
		};
	}

	public function test_token_with_extra_leading_space_authenticates(): void {
		$canonical = bin2hex( random_bytes( 16 ) );
		$this->install_token_row_for_canonical( $canonical, 42 );
		// Two spaces after "Bearer" — bug case.
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer  ' . $canonical;

		$result = AuthorizationServer::authenticate_bearer( false );

		$this->assertSame(
			42,
			$result,
			'Header "Bearer  TOKEN" (extra space) must trim to TOKEN and authenticate the bound user (L-1)'
		);
	}

	public function test_token_with_trailing_whitespace_authenticates(): void {
		$canonical = bin2hex( random_bytes( 16 ) );
		$this->install_token_row_for_canonical( $canonical, 99 );
		// Trailing newline — observed in the wild from sloppy curl / proxy chains.
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $canonical . "\n";

		$this->assertSame( 99, AuthorizationServer::authenticate_bearer( false ) );
	}

	public function test_token_with_tab_whitespace_authenticates(): void {
		$canonical = bin2hex( random_bytes( 16 ) );
		$this->install_token_row_for_canonical( $canonical, 13 );
		$_SERVER['HTTP_AUTHORIZATION'] = "Bearer \t" . $canonical . "\t";

		$this->assertSame( 13, AuthorizationServer::authenticate_bearer( false ) );
	}

	public function test_clean_bearer_header_still_authenticates(): void {
		// Regression: the trim must not break the canonical "Bearer TOKEN" form.
		$canonical = bin2hex( random_bytes( 16 ) );
		$this->install_token_row_for_canonical( $canonical, 7 );
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $canonical;

		$this->assertSame( 7, AuthorizationServer::authenticate_bearer( false ) );
	}
}
