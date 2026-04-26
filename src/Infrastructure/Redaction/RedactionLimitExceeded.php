<?php
/**
 * Raised when redaction traversal exceeds the configured depth or node limit.
 *
 * Caller MUST treat this as a fatal redaction failure and return a transport-level
 * error rather than emit a partially-redacted response — partial redaction is a
 * silent leak, not a graceful degradation.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Infrastructure\Redaction;

use RuntimeException;

/**
 * Redaction guard breach.
 */
final class RedactionLimitExceeded extends RuntimeException {}
