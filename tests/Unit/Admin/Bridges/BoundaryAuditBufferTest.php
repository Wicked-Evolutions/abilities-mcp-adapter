<?php
/**
 * Tests for BoundaryAuditBuffer — captures OAuth boundary events into a
 * bounded ring buffer for the Connected Bridges audit slice.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Admin\Bridges
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Admin\Bridges;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Admin\Bridges\BoundaryAuditBuffer;

final class BoundaryAuditBufferTest extends TestCase {

	protected function setUp(): void {
		BoundaryAuditBuffer::clear();
	}

	public function test_captures_oauth_events_to_buffer(): void {
		BoundaryAuditBuffer::capture( 'boundary.oauth_authorization_granted', array( 'client_id' => 'cid', 'user_id' => 7 ) );
		$entries = BoundaryAuditBuffer::read();
		$this->assertCount( 1, $entries );
		$this->assertSame( 'boundary.oauth_authorization_granted', $entries[0]['event'] );
		$this->assertSame( 'cid', $entries[0]['client_id'] );
		$this->assertSame( 7, $entries[0]['user_id'] );
	}

	public function test_ignores_non_oauth_events(): void {
		BoundaryAuditBuffer::capture( 'boundary.session_created', array( 'client_id' => 'cid' ) );
		$this->assertEmpty( BoundaryAuditBuffer::read() );
	}

	public function test_buffer_is_bounded_to_max_entries(): void {
		for ( $i = 0; $i < BoundaryAuditBuffer::MAX_ENTRIES + 5; $i++ ) {
			BoundaryAuditBuffer::capture( 'boundary.oauth_token_issued', array( 'client_id' => 'c' . $i ) );
		}
		$entries = BoundaryAuditBuffer::read();
		$this->assertCount( BoundaryAuditBuffer::MAX_ENTRIES, $entries );
		// Last entry should be the most recent.
		$this->assertSame( 'c' . ( BoundaryAuditBuffer::MAX_ENTRIES + 4 ), end( $entries )['client_id'] );
	}

	public function test_records_reason_and_error_code_when_present(): void {
		BoundaryAuditBuffer::capture( 'boundary.oauth_authorize_error', array(
			'client_id'  => 'cid',
			'reason'     => 'redirectable_validation_failed',
			'error_code' => 'invalid_scope',
		) );
		$entries = BoundaryAuditBuffer::read();
		$this->assertSame( 'redirectable_validation_failed', $entries[0]['reason'] );
		$this->assertSame( 'invalid_scope', $entries[0]['error_code'] );
	}

	public function test_handles_missing_optional_fields_gracefully(): void {
		BoundaryAuditBuffer::capture( 'boundary.oauth_invalid_token', array() );
		$entries = BoundaryAuditBuffer::read();
		$this->assertCount( 1, $entries );
		$this->assertSame( '', $entries[0]['client_id'] );
		$this->assertSame( 0, $entries[0]['user_id'] );
		$this->assertSame( '', $entries[0]['reason'] );
	}
}
