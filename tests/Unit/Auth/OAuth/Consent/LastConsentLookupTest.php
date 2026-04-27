<?php
/**
 * Tests for LastConsentLookup — record + read of the H.2.4 silent-cap timestamp.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\LastConsentLookup;

final class LastConsentLookupTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_options'] = array();
	}

	public function test_returns_null_when_no_consent_recorded(): void {
		$this->assertNull( LastConsentLookup::timestamp_for( 'client-x', 1 ) );
		$this->assertNull( LastConsentLookup::days_since( 'client-x', 1, time() ) );
	}

	public function test_record_then_read_returns_same_timestamp(): void {
		LastConsentLookup::record( 'client-x', 1, 1_700_000_000 );
		$this->assertSame( 1_700_000_000, LastConsentLookup::timestamp_for( 'client-x', 1 ) );
	}

	public function test_record_is_per_pair(): void {
		LastConsentLookup::record( 'client-a', 1, 1_700_000_000 );
		LastConsentLookup::record( 'client-b', 1, 1_700_001_000 );
		LastConsentLookup::record( 'client-a', 2, 1_700_002_000 );

		$this->assertSame( 1_700_000_000, LastConsentLookup::timestamp_for( 'client-a', 1 ) );
		$this->assertSame( 1_700_001_000, LastConsentLookup::timestamp_for( 'client-b', 1 ) );
		$this->assertSame( 1_700_002_000, LastConsentLookup::timestamp_for( 'client-a', 2 ) );
	}

	public function test_days_since_returns_floor_of_elapsed_days(): void {
		$now = 1_700_000_000;
		LastConsentLookup::record( 'client-x', 1, $now - ( 5 * 86400 ) - 3600 ); // 5 days, 1 hour
		$this->assertSame( 5, LastConsentLookup::days_since( 'client-x', 1, $now ) );
	}

	public function test_days_since_returns_zero_for_future_consent(): void {
		// Defensive — clock skew shouldn't underflow.
		$now = 1_700_000_000;
		LastConsentLookup::record( 'client-x', 1, $now + 3600 );
		$this->assertSame( 0, LastConsentLookup::days_since( 'client-x', 1, $now ) );
	}
}
