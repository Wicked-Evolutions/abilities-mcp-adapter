<?php
/**
 * Interface for MCP observability handlers.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Infrastructure\Observability\Contracts;

/**
 * Interface for handling MCP observability metrics and tracking.
 *
 * This interface defines the contract for observability handlers that can
 * track metrics like request counts, timing, and error rates in the MCP adapter.
 * Concrete implementations can integrate with various observability systems.
 */
interface McpObservabilityHandlerInterface {

	/**
	 * Emit a countable event for tracking with optional timing data.
	 *
	 * @param string     $event The event name to record.
	 * @param array      $tags Optional tags to attach to the event.
	 * @param float|null $duration_ms Optional duration in milliseconds for timing measurements.
	 *
	 * @return void
	 */
	public function record_event( string $event, array $tags = array(), ?float $duration_ms = null ): void;
}
