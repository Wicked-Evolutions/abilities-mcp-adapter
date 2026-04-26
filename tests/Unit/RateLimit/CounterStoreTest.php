<?php
/**
 * Tests for CounterStore.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

namespace WickedEvolutions\McpAdapter\Tests\Unit\RateLimit;

use WickedEvolutions\McpAdapter\RateLimit\CounterStore;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class CounterStoreTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		$GLOBALS['wp_test_transients']      = array();
		$GLOBALS['wp_test_object_cache']    = array();
		$GLOBALS['wp_test_using_ext_cache'] = false;
	}

	public function test_transient_backend_increments(): void {
		$store = new CounterStore( CounterStore::BACKEND_TRANSIENT );
		$this->assertSame( CounterStore::BACKEND_TRANSIENT, $store->backend() );
		$this->assertSame( 1, $store->increment( 'k', 120 ) );
		$this->assertSame( 2, $store->increment( 'k', 120 ) );
		$this->assertSame( 2, $store->get( 'k' ) );
	}

	public function test_object_cache_backend_used_when_external_cache_present(): void {
		wp_using_ext_object_cache( true );
		$store = new CounterStore();
		$this->assertSame( CounterStore::BACKEND_OBJECT_CACHE, $store->backend() );
		$this->assertSame( 1, $store->increment( 'k', 120 ) );
		$this->assertSame( 2, $store->increment( 'k', 120 ) );
		$this->assertSame( 2, $store->get( 'k' ) );
	}

	public function test_object_cache_falls_back_when_no_external_cache(): void {
		$store = new CounterStore();
		$this->assertSame( CounterStore::BACKEND_TRANSIENT, $store->backend() );
	}
}
