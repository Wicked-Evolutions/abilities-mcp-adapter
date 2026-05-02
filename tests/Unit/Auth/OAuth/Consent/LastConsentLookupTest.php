<?php
/**
 * Tests for LastConsentLookup — record + read of the H.2.4 silent-cap timestamp.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\ConsentDecision;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\ConsentDecisionEvaluator;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\LastConsentLookup;

final class LastConsentLookupTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_options'] = array();
		$GLOBALS['wp_test_filters'] = array();
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

	// ─── M-8 fail-closed contract ───────────────────────────────────────────────
	//
	// Audit (2026-04-27): "no fail-closed if the lookup throws."
	// Verified contract: any Throwable from the option backend → null →
	// ConsentDecisionEvaluator routes to RENDER_FULL ('first_authorization'),
	// never auto-approve.

	public function test_returns_null_when_pre_option_filter_throws(): void {
		$client_id = 'client-x';
		$user_id   = 1;
		$key       = 'abilities_oauth_last_consent_' . sha1( $client_id . '|' . $user_id );

		add_filter( 'pre_option_' . $key, function () {
			throw new \RuntimeException( 'simulated filter failure' );
		} );

		$this->assertNull( LastConsentLookup::timestamp_for( $client_id, $user_id ) );
	}

	public function test_days_since_returns_null_when_lookup_throws(): void {
		// days_since() reads via timestamp_for(), so it inherits the fail-closed
		// contract. Locked in so a future refactor can't leak an unhandled throw.
		$client_id = 'client-x';
		$user_id   = 1;
		$key       = 'abilities_oauth_last_consent_' . sha1( $client_id . '|' . $user_id );

		add_filter( 'pre_option_' . $key, function () {
			throw new \RuntimeException( 'simulated filter failure' );
		} );

		$this->assertNull( LastConsentLookup::days_since( $client_id, $user_id, time() ) );
	}

	public function test_throwing_lookup_routes_consent_decision_to_full_consent(): void {
		// End-to-end fail-closed verification: even with a prior token grant of
		// the exact same scope set well within the silent cap, a throwing lookup
		// must route to RENDER_FULL — never AUTO_APPROVE.
		$client_id = 'client-y';
		$user_id   = 2;
		$key       = 'abilities_oauth_last_consent_' . sha1( $client_id . '|' . $user_id );

		add_filter( 'pre_option_' . $key, function () {
			throw new \RuntimeException( 'simulated boom' );
		} );

		$last_interactive = LastConsentLookup::timestamp_for( $client_id, $user_id );
		$this->assertNull( $last_interactive );

		$decision = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:content:read' ),
			array( 'abilities:content:read' ), // prior grant on a non-sensitive scope
			$last_interactive,
			time(),
			365
		);

		$this->assertSame( ConsentDecision::RENDER_FULL, $decision->action );
		$this->assertSame( 'first_authorization', $decision->reason );
	}

	public function test_returns_null_when_stored_value_is_empty_string(): void {
		// Defensive: an option corrupted to an empty string must not coerce to
		// 0 and produce $silent_seconds == $now → fall through into auto-approve
		// territory if the cap were ever zero. Empty-string → null → RENDER_FULL.
		$client_id = 'client-x';
		$user_id   = 1;
		$key       = 'abilities_oauth_last_consent_' . sha1( $client_id . '|' . $user_id );
		$GLOBALS['wp_test_options'][ $key ] = '';

		$this->assertNull( LastConsentLookup::timestamp_for( $client_id, $user_id ) );
	}
}
