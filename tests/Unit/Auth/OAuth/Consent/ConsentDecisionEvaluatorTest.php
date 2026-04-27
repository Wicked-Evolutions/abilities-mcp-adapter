<?php
/**
 * Tests for ConsentDecisionEvaluator — the heart of Phase 3 routing.
 *
 * Binding sources:
 *   - Sub-issue #32 auto-approve contract
 *   - Appendix H.2.4 (silent-cap)
 *   - Appendix H.3.4 (sensitive scopes always show consent)
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\ConsentDecision;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\ConsentDecisionEvaluator;

final class ConsentDecisionEvaluatorTest extends TestCase {

	private const NOW = 1_700_000_000;
	private const DAY = 86400;

	// ─── Auto-approve happy path ─────────────────────────────────────────────────

	public function test_auto_approves_when_scopes_unchanged_and_within_silent_cap(): void {
		$decision = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:content:read', 'abilities:content:write' ),
			array( 'abilities:content:read', 'abilities:content:write' ),
			self::NOW - ( 100 * self::DAY ), // 100 days ago
			self::NOW,
			365
		);
		$this->assertTrue( $decision->is_auto_approve() );
		$this->assertSame( ConsentDecision::AUTO_APPROVE, $decision->action );
	}

	public function test_auto_approves_when_requested_is_subset_of_previously_granted(): void {
		// Reduction is OK — no new scopes, no sensitive scopes.
		$decision = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:content:read' ),
			array( 'abilities:content:read', 'abilities:content:write' ),
			self::NOW - ( 10 * self::DAY ),
			self::NOW,
			365
		);
		$this->assertTrue( $decision->is_auto_approve() );
	}

	// ─── No prior grant ──────────────────────────────────────────────────────────

	public function test_renders_full_consent_when_no_prior_interactive_grant(): void {
		$decision = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:content:read' ),
			array(),
			null,
			self::NOW,
			365
		);
		$this->assertTrue( $decision->is_render_full() );
		$this->assertSame( 'first_authorization', $decision->reason );
	}

	// ─── H.2.4 silent-cap ────────────────────────────────────────────────────────

	public function test_renders_full_consent_when_silent_cap_exceeded_even_for_unchanged_scopes(): void {
		$decision = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:content:read' ),
			array( 'abilities:content:read' ),
			self::NOW - ( 400 * self::DAY ), // > 365 days ago
			self::NOW,
			365
		);
		$this->assertTrue( $decision->is_render_full() );
		$this->assertSame( 'silent_cap_exceeded', $decision->reason );
	}

	public function test_renders_full_consent_when_silent_cap_exceeded_at_exact_boundary_plus_one_second(): void {
		// 1 second past the cap → must consent.
		$decision = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:content:read' ),
			array( 'abilities:content:read' ),
			self::NOW - ( 365 * self::DAY ) - 1,
			self::NOW,
			365
		);
		$this->assertTrue( $decision->is_render_full() );
		$this->assertSame( 'silent_cap_exceeded', $decision->reason );
	}

	public function test_silent_cap_can_be_set_to_one_day_for_high_security_sites(): void {
		// 25 hours since last consent, cap = 1 day → must re-consent.
		$decision = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:content:read' ),
			array( 'abilities:content:read' ),
			self::NOW - ( self::DAY + 3600 ),
			self::NOW,
			1
		);
		$this->assertTrue( $decision->is_render_full() );
		$this->assertSame( 'silent_cap_exceeded', $decision->reason );
	}

	// ─── H.3.4 sensitive scopes always show consent ──────────────────────────────

	public function test_renders_full_consent_when_sensitive_scope_requested_even_if_previously_granted(): void {
		$decision = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:settings:read' ),
			array( 'abilities:settings:read' ), // PREVIOUSLY granted
			self::NOW - ( 5 * self::DAY ),
			self::NOW,
			365
		);
		$this->assertTrue( $decision->is_render_full() );
		$this->assertSame( 'sensitive_scope_requested', $decision->reason );
	}

	public function test_renders_full_consent_when_any_one_scope_in_set_is_sensitive(): void {
		$decision = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:content:read', 'abilities:settings:write' ),
			array( 'abilities:content:read', 'abilities:settings:write' ),
			self::NOW - self::DAY,
			self::NOW,
			365
		);
		$this->assertTrue( $decision->is_render_full() );
		$this->assertSame( 'sensitive_scope_requested', $decision->reason );
		$this->assertContains( 'abilities:settings:write', $decision->sensitive );
	}

	public function test_all_canonical_sensitive_modules_trigger_full_consent(): void {
		// Verify every module listed in Appendix H.3.4 routes to full consent.
		$modules = array( 'settings', 'users', 'filesystem', 'cron', 'plugins', 'multisite' );
		foreach ( $modules as $module ) {
			$scope    = "abilities:{$module}:read";
			$decision = ConsentDecisionEvaluator::evaluate(
				array( $scope ),
				array( $scope ),
				self::NOW - self::DAY,
				self::NOW,
				365
			);
			$this->assertTrue( $decision->is_render_full(), "{$module} sensitive scope must force full consent" );
			$this->assertSame( 'sensitive_scope_requested', $decision->reason );
		}
	}

	// ─── Incremental consent (new non-sensitive scopes) ──────────────────────────

	public function test_renders_incremental_when_only_new_non_sensitive_scopes_added(): void {
		$decision = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:content:read', 'abilities:taxonomies:read' ),
			array( 'abilities:content:read' ),
			self::NOW - ( 30 * self::DAY ),
			self::NOW,
			365
		);
		$this->assertTrue( $decision->is_render_incremental() );
		$this->assertSame( 'new_non_sensitive_scopes', $decision->reason );
		$this->assertSame( array( 'abilities:taxonomies:read' ), $decision->newly_added );
	}

	public function test_renders_full_when_new_scope_is_sensitive_and_others_are_not(): void {
		// New scope set includes a sensitive one — full consent, not incremental.
		$decision = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:content:read', 'abilities:plugins:write' ),
			array( 'abilities:content:read' ),
			self::NOW - self::DAY,
			self::NOW,
			365
		);
		$this->assertTrue( $decision->is_render_full() );
		$this->assertSame( 'sensitive_scope_requested', $decision->reason );
	}

	// ─── Determinism / normalization ─────────────────────────────────────────────

	public function test_decision_is_independent_of_input_order_or_duplicates(): void {
		$d1 = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:content:read', 'abilities:content:write', 'abilities:content:read' ),
			array( 'abilities:content:write', 'abilities:content:read' ),
			self::NOW - self::DAY,
			self::NOW,
			365
		);
		$d2 = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:content:write', 'abilities:content:read' ),
			array( 'abilities:content:read', 'abilities:content:write' ),
			self::NOW - self::DAY,
			self::NOW,
			365
		);
		$this->assertSame( $d1->action, $d2->action );
		$this->assertSame( $d1->requested, $d2->requested );
	}

	// ─── Decision-precedence ordering ────────────────────────────────────────────

	public function test_silent_cap_takes_precedence_over_sensitive_scope_check(): void {
		// Past silent cap AND sensitive scope — reason is silent cap (we hit it first).
		$decision = ConsentDecisionEvaluator::evaluate(
			array( 'abilities:settings:read' ),
			array( 'abilities:settings:read' ),
			self::NOW - ( 400 * self::DAY ),
			self::NOW,
			365
		);
		$this->assertTrue( $decision->is_render_full() );
		$this->assertSame( 'silent_cap_exceeded', $decision->reason );
	}
}
