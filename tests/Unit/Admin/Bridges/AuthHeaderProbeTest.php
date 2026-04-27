<?php
/**
 * Tests for AuthHeaderProbe — populates the H.2.6 diagnostic from a rolling counter.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Admin\Bridges
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Admin\Bridges;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Admin\Bridges\AuthHeaderProbe;

final class AuthHeaderProbeTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_options'] = array();
		AuthHeaderProbe::clear();
	}

	public function test_returns_existing_when_no_observations_yet(): void {
		$result = AuthHeaderProbe::resolve_status( null );
		$this->assertNull( $result, 'No observations means: defer to placeholder default.' );
	}

	public function test_returns_ok_when_all_recent_requests_had_header(): void {
		for ( $i = 0; $i < 5; $i++ ) {
			AuthHeaderProbe::record( true );
		}
		$result = AuthHeaderProbe::resolve_status( null );
		$this->assertSame( 'ok', $result['state'] );
	}

	public function test_returns_warn_when_no_recent_requests_had_header(): void {
		for ( $i = 0; $i < 3; $i++ ) {
			AuthHeaderProbe::record( false );
		}
		$result = AuthHeaderProbe::resolve_status( null );
		$this->assertSame( 'warn', $result['state'] );
		$this->assertNotEmpty( $result['docs_url'] );
	}

	public function test_returns_warn_when_some_recent_requests_were_missing_header(): void {
		AuthHeaderProbe::record( true );
		AuthHeaderProbe::record( true );
		AuthHeaderProbe::record( false );
		$result = AuthHeaderProbe::resolve_status( null );
		$this->assertSame( 'warn', $result['state'] );
	}

	public function test_window_is_capped_at_100_observations(): void {
		// Push 150 observations — only the last 100 should be considered.
		for ( $i = 0; $i < 150; $i++ ) {
			AuthHeaderProbe::record( true );
		}
		$result = AuthHeaderProbe::resolve_status( null );
		$this->assertSame( 'ok', $result['state'] );
		$this->assertStringContainsString( '100', $result['message'] );
	}
}
