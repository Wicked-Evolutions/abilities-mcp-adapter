<?php
/**
 * Tests for BridgeRowProjector — pure projection of a Connected Bridges row.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Admin\Bridges
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Admin\Bridges;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Admin\Bridges\BridgeRowProjector;

final class BridgeRowProjectorTest extends TestCase {

	private const NOW = 1_700_000_000;
	private const DAY = 86400;

	public function test_projects_basic_row(): void {
		$client = (object) array(
			'client_id'        => 'cid-1',
			'client_name'      => 'My Bridge',
			'software_id'      => 'com.example.bridge',
			'software_version' => '1.2.3',
			'scopes'           => 'abilities:read',
			'registered_at'    => '2026-01-01 00:00:00',
		);
		$token = (object) array(
			'user_id'      => 7,
			'scope'        => 'abilities:content:read abilities:content:write',
			'last_used_at' => '2026-04-25 08:00:00',
			'expires_at'   => '2026-05-25 08:00:00',
		);

		$row = BridgeRowProjector::project( $client, $token, self::NOW - ( 100 * self::DAY ), self::NOW, 365 );

		$this->assertSame( 'cid-1', $row['client_id'] );
		$this->assertSame( 'My Bridge', $row['client_name'] );
		$this->assertSame( 'com.example.bridge 1.2.3', $row['software'] );
		$this->assertSame( 7, $row['user_id'] );
		$this->assertSame( array( 'abilities:content:read', 'abilities:content:write' ), $row['scopes'] );
		$this->assertSame( '2026-04-25 08:00:00', $row['last_used_at'] );
		$this->assertSame( 100, $row['last_consent_days'] );
		$this->assertFalse( $row['show_silent_warning'] );
	}

	public function test_silent_warning_triggers_at_threshold_minus_30_days(): void {
		$client = (object) array( 'client_id' => 'cid-1', 'client_name' => 'X' );
		$token  = (object) array( 'user_id' => 1, 'scope' => 'abilities:read', 'last_used_at' => '', 'expires_at' => '' );

		// Cap = 365, threshold = 335. At 334 days, no warning. At 335, warning.
		$row_below = BridgeRowProjector::project( $client, $token, self::NOW - ( 334 * self::DAY ), self::NOW, 365 );
		$row_at    = BridgeRowProjector::project( $client, $token, self::NOW - ( 335 * self::DAY ), self::NOW, 365 );

		$this->assertFalse( $row_below['show_silent_warning'] );
		$this->assertTrue(  $row_at['show_silent_warning'] );
	}

	public function test_silent_warning_false_when_no_last_consent(): void {
		$client = (object) array( 'client_id' => 'cid-1', 'client_name' => 'X' );
		$token  = (object) array( 'user_id' => 1, 'scope' => '', 'last_used_at' => null, 'expires_at' => null );

		$row = BridgeRowProjector::project( $client, $token, null, self::NOW, 365 );
		$this->assertNull( $row['last_consent_days'] );
		$this->assertFalse( $row['show_silent_warning'] );
	}

	public function test_handles_missing_token(): void {
		$client = (object) array(
			'client_id'   => 'cid-1',
			'client_name' => 'No-token bridge',
			'scopes'      => 'abilities:read',
		);

		$row = BridgeRowProjector::project( $client, null, null, self::NOW, 365 );

		$this->assertSame( 0, $row['user_id'] );
		$this->assertSame( array( 'abilities:read' ), $row['scopes'], 'falls back to client.scopes when token absent' );
		$this->assertNull( $row['last_used_at'] );
		$this->assertNull( $row['expires_at'] );
	}

	public function test_software_string_omits_version_when_blank(): void {
		$client = (object) array(
			'client_id'        => 'cid-1',
			'client_name'      => 'X',
			'software_id'      => 'com.example.bridge',
			'software_version' => '',
		);
		$row = BridgeRowProjector::project( $client, null, null, self::NOW, 365 );
		$this->assertSame( 'com.example.bridge', $row['software'] );
	}
}
