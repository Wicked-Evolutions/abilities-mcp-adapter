<?php
/**
 * Tests for PolicyStore — Appendix H.2.4 silent-cap resolution.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\PolicyStore;

final class PolicyStoreTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_options']  = array();
		$GLOBALS['wp_test_filters']  = array();
	}

	public function test_default_when_no_option_or_filter(): void {
		$this->assertSame( PolicyStore::DEFAULT_SILENT_DAYS, PolicyStore::consent_max_silent_days() );
	}

	public function test_option_overrides_default(): void {
		update_option( PolicyStore::OPTION_SILENT_DAYS, 90 );
		$this->assertSame( 90, PolicyStore::consent_max_silent_days() );
	}

	public function test_filter_overrides_option(): void {
		update_option( PolicyStore::OPTION_SILENT_DAYS, 90 );
		add_filter( PolicyStore::OPTION_SILENT_DAYS, fn( $val ) => 30 );
		$this->assertSame( 30, PolicyStore::consent_max_silent_days() );
	}

	public function test_clamped_below_min(): void {
		update_option( PolicyStore::OPTION_SILENT_DAYS, 0 );
		$this->assertSame( PolicyStore::DEFAULT_SILENT_DAYS, PolicyStore::consent_max_silent_days(), '0 collapses to default before clamping.' );

		add_filter( PolicyStore::OPTION_SILENT_DAYS, fn( $val ) => -5 );
		$this->assertSame( PolicyStore::DEFAULT_SILENT_DAYS, PolicyStore::consent_max_silent_days(), 'negative filter result collapses to upstream value.' );
	}

	public function test_clamped_above_max(): void {
		update_option( PolicyStore::OPTION_SILENT_DAYS, 9_999 );
		$this->assertSame( PolicyStore::MAX_SILENT_DAYS, PolicyStore::consent_max_silent_days() );
	}

	public function test_clamp_helper_respects_floor_and_ceiling(): void {
		$this->assertSame( PolicyStore::MIN_SILENT_DAYS, PolicyStore::clamp( -1 ) );
		$this->assertSame( PolicyStore::MIN_SILENT_DAYS, PolicyStore::clamp( 0 ) );
		$this->assertSame( PolicyStore::MAX_SILENT_DAYS, PolicyStore::clamp( 100_000 ) );
		$this->assertSame( 100, PolicyStore::clamp( 100 ) );
	}
}
