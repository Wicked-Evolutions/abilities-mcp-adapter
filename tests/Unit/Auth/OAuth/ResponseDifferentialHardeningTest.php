<?php
/**
 * H-1: Error-response differential between revoked vs invalid/expired tokens.
 *
 * Pre-fix: revoked tokens returned error_description "The access token has
 * been revoked." while expired/missing returned "The access token is invalid."
 * A polling attacker could distinguish revocation from natural expiry.
 *
 * After fix: all invalid-token paths return the same error_description so
 * the observable difference is zero.
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

final class ResponseDifferentialHardeningTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		parent::setUp();
		$this->original_wpdb       = $GLOBALS['wpdb'];
		$GLOBALS['wp_test_filters'] = array();
		OAuthRequestContext::reset();
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb']            = $this->original_wpdb;
		$GLOBALS['wp_test_filters'] = array();
		unset( $_SERVER['REQUEST_URI'], $_SERVER['HTTP_AUTHORIZATION'] );
		OAuthRequestContext::reset();
		parent::tearDown();
	}

	private function set_mcp_request( string $token = 'some-token' ): void {
		$_SERVER['REQUEST_URI']        = '/wp-json/mcp/mcp-adapter-default-server';
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
	}

	private function install_row( object $row ): void {
		$GLOBALS['wpdb'] = new class( $row ) {
			public string $prefix = 'wp_';
			private object $row;
			public function __construct( object $row ) { $this->row = $row; }
			public function prepare( $q, ...$a )     { return $q; }
			public function get_row( $q )            { return $this->row; }
			public function get_results( $q )        { return array(); }
			public function get_var( $q )            { return null; }
			public function update( $t, $d, $w, $f = null, $wf = null ) { return 1; }
			public function insert( $t, $d, $f = null )                  { return 1; }
			public function query( $sql )            { return true; }
		};
	}

	private function get_registered_challenge_description(): string {
		$entries = $GLOBALS['wp_test_filters']['rest_post_dispatch'] ?? array();
		if ( empty( $entries ) ) {
			return '';
		}
		$last    = end( $entries );
		$closure = $last['cb'];
		$rf      = new \ReflectionFunction( $closure );
		$vars    = $rf->getStaticVariables();
		return (string) ( $vars['description'] ?? '' );
	}

	private function make_revoked_row(): object {
		$row            = new \stdClass();
		$row->id        = 1;
		$row->client_id = 'cl_test';
		$row->user_id   = 7;
		$row->scope     = 'abilities:content:read';
		$row->resource  = 'https://example.com/wp-json/mcp/mcp-adapter-default-server';
		$row->token_hash = 'h';
		$row->expires_at = ( new \DateTimeImmutable( '+1 hour', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s' );
		$row->revoked   = 1;
		return $row;
	}

	/**
	 * Core assertion: revoked token error_description must equal invalid/expired.
	 */
	public function test_revoked_token_returns_same_error_description_as_invalid(): void {
		$this->install_row( $this->make_revoked_row() );
		$this->set_mcp_request();

		AuthorizationServer::authenticate_bearer( false );

		$description = $this->get_registered_challenge_description();
		$this->assertSame(
			'The access token is invalid.',
			$description,
			'H-1: revoked token must return identical error_description to invalid/expired'
		);
	}

	/**
	 * Regression lock-in: the old string must NOT appear in any challenge path.
	 */
	public function test_old_revoked_description_never_appears(): void {
		$this->install_row( $this->make_revoked_row() );
		$this->set_mcp_request();

		AuthorizationServer::authenticate_bearer( false );

		$description = $this->get_registered_challenge_description();
		$this->assertStringNotContainsString(
			'revoked',
			strtolower( $description ),
			'error_description must not mention revocation to the client'
		);
	}

	/**
	 * Expired tokens still use the same error_description (no regression).
	 */
	public function test_expired_token_description_unchanged(): void {
		$row            = new \stdClass();
		$row->id        = 2;
		$row->client_id = 'cl_test';
		$row->user_id   = 7;
		$row->scope     = 'abilities:content:read';
		$row->resource  = 'https://example.com/wp-json/mcp/mcp-adapter-default-server';
		$row->token_hash = 'h';
		$row->expires_at = ( new \DateTimeImmutable( '-1 hour', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s' );
		$row->revoked   = 0;
		$this->install_row( $row );
		$this->set_mcp_request();

		AuthorizationServer::authenticate_bearer( false );

		$description = $this->get_registered_challenge_description();
		$this->assertSame( 'The access token is invalid.', $description );
	}
}
