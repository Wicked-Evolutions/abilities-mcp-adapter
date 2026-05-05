<?php
/**
 * #88: AuthorizationCodeStore persists selected_role.
 *
 * Pins that AuthorizationCodeStore::store() forwards the operator-selected
 * role onto the kl_oauth_codes row. Together with TokenStore round-trip
 * coverage, this proves the auth-code → token chain carries the role.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationCodeStore;

final class AuthorizationCodeStoreSelectedRoleTest extends TestCase {

	private object $original_wpdb;

	protected function setUp(): void {
		$this->original_wpdb = $GLOBALS['wpdb'];
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->original_wpdb;
	}

	public function test_store_persists_supplied_selected_role(): void {
		$captured = null;
		$GLOBALS['wpdb'] = new class( $captured ) {
			public string $prefix     = 'wp_';
			public string $last_error = '';
			public function __construct( public &$captured ) {}
			public function insert( $t, $data, $format = null ) {
				$this->captured = $data;
				return 1;
			}
		};

		AuthorizationCodeStore::store(
			str_repeat( 'a', 64 ),
			'client-x',
			7,
			'https://example.com/cb',
			'abilities:content:read',
			'https://example.com/wp-json/mcp/x',
			str_repeat( 'b', 43 ),
			600,
			'editor'
		);

		$this->assertArrayHasKey( 'selected_role', $GLOBALS['wpdb']->captured );
		$this->assertSame( 'editor', $GLOBALS['wpdb']->captured['selected_role'] );
	}

	public function test_store_persists_empty_selected_role_when_omitted(): void {
		// Default-arg path — single-role op or auto-approve flow. Empty string
		// is the "no downgrade" signal consumed by SelectedRoleEnforcer.
		$captured = null;
		$GLOBALS['wpdb'] = new class( $captured ) {
			public string $prefix     = 'wp_';
			public string $last_error = '';
			public function __construct( public &$captured ) {}
			public function insert( $t, $data, $format = null ) {
				$this->captured = $data;
				return 1;
			}
		};

		AuthorizationCodeStore::store(
			str_repeat( 'a', 64 ),
			'client-x',
			7,
			'https://example.com/cb',
			'abilities:content:read',
			'https://example.com/wp-json/mcp/x',
			str_repeat( 'b', 43 )
			// no $ttl_seconds, no $selected_role — defaults: 600 / ''
		);

		$this->assertArrayHasKey( 'selected_role', $GLOBALS['wpdb']->captured );
		$this->assertSame( '', $GLOBALS['wpdb']->captured['selected_role'] );
	}
}
