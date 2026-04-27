<?php
/**
 * Tests for RenderedScopeNonce — Appendix H.4.5 server-bound consent nonce.
 *
 * Critical invariants:
 *   - Server is the ONLY source of truth for "what scope set was rendered."
 *   - Submitted scope set must be a subset of the rendered scope set.
 *   - Nonce is single-use (atomic redeem on first call).
 *   - Mismatched user_id, client_id, redirect_uri, or state → reject.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\RenderedScopeNonce;

final class RenderedScopeNonceTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_transients'] = array();
	}

	private const RENDERED  = array( 'abilities:content:read', 'abilities:content:write', 'abilities:taxonomies:read' );
	private const USER_ID   = 99;
	private const CLIENT    = 'client-abc';
	private const REDIRECT  = 'http://127.0.0.1/cb';
	private const STATE     = 'state-xyz';

	public function test_issued_nonce_can_be_redeemed_with_matching_request(): void {
		$nonce   = RenderedScopeNonce::issue( self::RENDERED, self::USER_ID, self::CLIENT, self::REDIRECT, self::STATE );
		$payload = RenderedScopeNonce::redeem( $nonce );

		$this->assertIsArray( $payload );
		$this->assertSame( self::USER_ID, $payload['user_id'] );
		$this->assertSame( self::CLIENT, $payload['client_id'] );
		$this->assertSame( self::REDIRECT, $payload['redirect_uri'] );
		$this->assertSame( hash( 'sha256', self::STATE ), $payload['state_hash'] );
		$this->assertSame( self::RENDERED, $payload['rendered_scopes'] );
	}

	public function test_redeem_is_single_use(): void {
		$nonce = RenderedScopeNonce::issue( self::RENDERED, self::USER_ID, self::CLIENT, self::REDIRECT, self::STATE );
		$first  = RenderedScopeNonce::redeem( $nonce );
		$second = RenderedScopeNonce::redeem( $nonce );

		$this->assertIsArray( $first );
		$this->assertNull( $second );
	}

	public function test_redeem_returns_null_for_unknown_nonce(): void {
		$this->assertNull( RenderedScopeNonce::redeem( 'never-issued' ) );
	}

	public function test_redeem_returns_null_for_empty_nonce(): void {
		$this->assertNull( RenderedScopeNonce::redeem( '' ) );
	}

	// ─── Subset validation (the H.4.5 core protection) ──────────────────────────

	public function test_subset_is_valid_when_submitted_equals_rendered(): void {
		$payload = $this->payload();
		$this->assertTrue(
			RenderedScopeNonce::submitted_subset_is_valid( $payload, self::USER_ID, self::CLIENT, self::REDIRECT, self::STATE, self::RENDERED )
		);
	}

	public function test_subset_is_valid_when_submitted_is_proper_subset_of_rendered(): void {
		$payload = $this->payload();
		$this->assertTrue(
			RenderedScopeNonce::submitted_subset_is_valid( $payload, self::USER_ID, self::CLIENT, self::REDIRECT, self::STATE, array( 'abilities:content:read' ) )
		);
	}

	public function test_subset_is_invalid_when_submitted_contains_unrendered_scope(): void {
		// This is the browser-extension threat: form mutated to add a scope the server never rendered.
		$payload = $this->payload();
		$this->assertFalse(
			RenderedScopeNonce::submitted_subset_is_valid(
				$payload,
				self::USER_ID,
				self::CLIENT,
				self::REDIRECT,
				self::STATE,
				array( 'abilities:content:read', 'abilities:settings:write' )
			)
		);
	}

	public function test_subset_is_invalid_for_wrong_user(): void {
		$payload = $this->payload();
		$this->assertFalse(
			RenderedScopeNonce::submitted_subset_is_valid( $payload, 1234, self::CLIENT, self::REDIRECT, self::STATE, self::RENDERED )
		);
	}

	public function test_subset_is_invalid_for_wrong_client_id(): void {
		$payload = $this->payload();
		$this->assertFalse(
			RenderedScopeNonce::submitted_subset_is_valid( $payload, self::USER_ID, 'other-client', self::REDIRECT, self::STATE, self::RENDERED )
		);
	}

	public function test_subset_is_invalid_for_wrong_redirect_uri(): void {
		$payload = $this->payload();
		$this->assertFalse(
			RenderedScopeNonce::submitted_subset_is_valid( $payload, self::USER_ID, self::CLIENT, 'http://attacker/cb', self::STATE, self::RENDERED )
		);
	}

	public function test_subset_is_invalid_for_wrong_state(): void {
		$payload = $this->payload();
		$this->assertFalse(
			RenderedScopeNonce::submitted_subset_is_valid( $payload, self::USER_ID, self::CLIENT, self::REDIRECT, 'tampered-state', self::RENDERED )
		);
	}

	private function payload(): array {
		$nonce = RenderedScopeNonce::issue( self::RENDERED, self::USER_ID, self::CLIENT, self::REDIRECT, self::STATE );
		return RenderedScopeNonce::redeem( $nonce );
	}
}
