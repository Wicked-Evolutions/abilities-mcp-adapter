<?php
/**
 * H-9: redirect_uri loopback compare must be RFC 8252 §7.3 compliant.
 *
 * Pre-fix: ClientRegistry::redirect_uri_valid() compared loopback query
 * strings byte-for-byte. ?foo=1&bar=2 vs ?bar=2&foo=1, hello%20world vs
 * hello+world, and trailing-? differences all rejected.
 *
 * After fix: query strings on loopback URIs are normalized via
 * parse_str → ksort → http_build_query(PHP_QUERY_RFC3986). Same key/value
 * pairs in any order with any equivalent percent-encoding compare equal.
 *
 * Path normalisation is intentionally NOT applied — `/callback` and
 * `/callback/` remain distinct so client misconfiguration surfaces.
 *
 * Fragments on candidate or registered URI cause an outright reject
 * (RFC 6749 §3.1.2: "redirect_uri MUST NOT include a fragment component").
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\ClientRegistry;

final class RedirectUriNormalizeTest extends TestCase {

	private function client( array $registered ): object {
		$c = new \stdClass();
		$c->redirect_uris = json_encode( $registered );
		return $c;
	}

	// -------------------------------------------------------------------------
	// Query order normalisation
	// -------------------------------------------------------------------------

	public function test_loopback_query_param_order_normalized(): void {
		$c = $this->client( [ 'http://127.0.0.1/cb?foo=1&bar=2' ] );
		// Same pairs, opposite order — must validate.
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb?bar=2&foo=1' ) );
	}

	public function test_loopback_three_param_order_normalized(): void {
		$c = $this->client( [ 'http://127.0.0.1/cb?a=1&b=2&c=3' ] );
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb?c=3&a=1&b=2' ) );
	}

	// -------------------------------------------------------------------------
	// Percent-encoding normalisation
	// -------------------------------------------------------------------------

	public function test_loopback_space_encoded_as_percent20_or_plus_equivalent(): void {
		$c = $this->client( [ 'http://127.0.0.1/cb?key=hello%20world' ] );
		// Plus-encoded form (form-encoding default) must match percent-20 form.
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb?key=hello+world' ) );
	}

	public function test_loopback_percent_encoded_punctuation_normalized(): void {
		$c = $this->client( [ 'http://127.0.0.1/cb?email=a%40b.com' ] );
		// Unencoded @ — parse_str / http_build_query round-trip should produce equivalent normalised form.
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb?email=a@b.com' ) );
	}

	// -------------------------------------------------------------------------
	// Trailing ? equivalence
	// -------------------------------------------------------------------------

	public function test_loopback_no_query_matches_empty_query(): void {
		$c = $this->client( [ 'http://127.0.0.1/cb' ] );
		// parse_url returns no 'query' key for trailing-? — both sides normalise to ''.
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb?' ) );
	}

	// -------------------------------------------------------------------------
	// Different values still reject (the safety guarantee)
	// -------------------------------------------------------------------------

	public function test_loopback_different_value_rejected(): void {
		$c = $this->client( [ 'http://127.0.0.1/cb?foo=1' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb?foo=2' ) );
	}

	public function test_loopback_extra_param_rejected(): void {
		// Don't accept a superset of registered params.
		$c = $this->client( [ 'http://127.0.0.1/cb' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb?injected=evil' ) );
	}

	public function test_loopback_missing_param_rejected(): void {
		// And don't accept a subset either.
		$c = $this->client( [ 'http://127.0.0.1/cb?foo=1&bar=2' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb?foo=1' ) );
	}

	public function test_loopback_different_key_rejected(): void {
		$c = $this->client( [ 'http://127.0.0.1/cb?foo=1' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb?other=1' ) );
	}

	// -------------------------------------------------------------------------
	// Path normalisation NOT applied (intentional)
	// -------------------------------------------------------------------------

	public function test_loopback_path_trailing_slash_still_distinct(): void {
		// Documenting the deliberate non-normalisation choice — see PR body.
		$c = $this->client( [ 'http://127.0.0.1/cb' ] );
		$this->assertFalse(
			ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb/' ),
			'Path normalisation is intentionally NOT applied; trailing slash remains distinct'
		);
	}

	// -------------------------------------------------------------------------
	// Fragment rejection (RFC 6749 §3.1.2)
	// -------------------------------------------------------------------------

	public function test_candidate_with_fragment_rejected_loopback(): void {
		$c = $this->client( [ 'http://127.0.0.1/cb' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb#frag' ) );
	}

	public function test_candidate_with_fragment_rejected_https(): void {
		$c = $this->client( [ 'https://bridge.example.com/cb' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $c, 'https://bridge.example.com/cb#frag' ) );
	}

	public function test_candidate_with_empty_fragment_rejected(): void {
		// Even an empty fragment ('#' with nothing after) must reject.
		$c = $this->client( [ 'http://127.0.0.1/cb' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb#' ) );
	}

	public function test_registered_with_fragment_does_not_match(): void {
		// If somehow a fragmented URI was stored, it must not match anything.
		$c = $this->client( [ 'http://127.0.0.1/cb#frag' ] );
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb' ) );
	}

	// -------------------------------------------------------------------------
	// Existing port-ignore behaviour preserved
	// -------------------------------------------------------------------------

	public function test_loopback_port_still_ignored(): void {
		$c = $this->client( [ 'http://127.0.0.1/cb' ] );
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:1234/cb' ) );
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:65535/cb' ) );
	}

	public function test_loopback_port_ignored_with_query(): void {
		$c = $this->client( [ 'http://127.0.0.1/cb?state_seed=abc' ] );
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $c, 'http://127.0.0.1:9876/cb?state_seed=abc' ) );
	}

	public function test_loopback_ipv6(): void {
		$c = $this->client( [ 'http://[::1]/cb?x=1' ] );
		$this->assertTrue( ClientRegistry::redirect_uri_valid( $c, 'http://[::1]:5555/cb?x=1' ) );
	}

	// -------------------------------------------------------------------------
	// Non-loopback: exact-match preserved
	// -------------------------------------------------------------------------

	public function test_https_exact_match_still_required(): void {
		$c = $this->client( [ 'https://bridge.example.com/cb?foo=1' ] );
		// Non-loopback: query order matters (exact-match rule, H.1.2).
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $c, 'https://bridge.example.com/cb?foo=1&extra=2' ) );
	}

	public function test_https_non_normalized_compare(): void {
		$c = $this->client( [ 'https://bridge.example.com/cb?a=1&b=2' ] );
		// Different order — non-loopback exact-match rejects.
		$this->assertFalse( ClientRegistry::redirect_uri_valid( $c, 'https://bridge.example.com/cb?b=2&a=1' ) );
	}
}
