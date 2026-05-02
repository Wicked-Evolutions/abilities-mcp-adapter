<?php
/**
 * L-3 (#68): DCR sensitive-scope flag.
 *
 * Pins the contract for `RegisterEndpoint::classify_scopes()` — the helper
 * the DCR POST handler uses to compute (a) the valid scope set kept on the
 * registration record and (b) the subset of those that are sensitive and
 * will therefore require explicit operator consent at /oauth/authorize.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Endpoints
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Endpoints;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints\RegisterEndpoint;

final class RegisterEndpointClassifyScopesTest extends TestCase {

	public function test_empty_string_yields_empty_valid_and_sensitive(): void {
		$result = RegisterEndpoint::classify_scopes( '' );

		$this->assertSame( array(), $result['valid'] );
		$this->assertSame( array(), $result['sensitive'] );
	}

	public function test_only_non_sensitive_scopes_have_no_sensitive_flag(): void {
		$result = RegisterEndpoint::classify_scopes( 'abilities:read abilities:content:write' );

		$this->assertSame(
			array( 'abilities:read', 'abilities:content:write' ),
			$result['valid']
		);
		$this->assertSame( array(), $result['sensitive'] );
	}

	public function test_single_sensitive_scope_appears_in_both_arrays(): void {
		// Sensitive scopes stay in 'valid' — they are stored on the DCR record
		// and gated at /oauth/authorize, NOT rejected at registration.
		$result = RegisterEndpoint::classify_scopes( 'abilities:settings:write' );

		$this->assertSame( array( 'abilities:settings:write' ), $result['valid'] );
		$this->assertSame( array( 'abilities:settings:write' ), $result['sensitive'] );
	}

	public function test_mixed_scopes_only_sensitive_subset_is_flagged(): void {
		$result = RegisterEndpoint::classify_scopes(
			'abilities:read abilities:settings:write abilities:content:read abilities:plugins:delete'
		);

		$this->assertSame(
			array(
				'abilities:read',
				'abilities:settings:write',
				'abilities:content:read',
				'abilities:plugins:delete',
			),
			$result['valid']
		);
		$this->assertSame(
			array( 'abilities:settings:write', 'abilities:plugins:delete' ),
			$result['sensitive']
		);
	}

	public function test_unknown_scopes_dropped_from_both_arrays(): void {
		// RFC 7591 §2.1 — server may modify requested scope; unknown silently filtered.
		$result = RegisterEndpoint::classify_scopes(
			'abilities:read abilities:bogus:scope abilities:settings:read'
		);

		$this->assertSame(
			array( 'abilities:read', 'abilities:settings:read' ),
			$result['valid']
		);
		$this->assertSame( array( 'abilities:settings:read' ), $result['sensitive'] );
	}

	public function test_arrays_are_zero_indexed_after_filtering(): void {
		// Defensive: array_filter preserves keys, so without array_values the
		// JSON encoder would emit objects instead of arrays for any subset.
		$result = RegisterEndpoint::classify_scopes(
			'abilities:bogus:scope abilities:settings:write'
		);

		$this->assertSame( 0, array_key_first( $result['valid'] ) );
		$this->assertSame( 0, array_key_first( $result['sensitive'] ) );
	}
}
