<?php
/**
 * Value object describing how the authorize endpoint should route a request.
 *
 * Outcomes:
 *   - AUTO_APPROVE          mint a code immediately, no consent screen
 *   - RENDER_FULL           show the full consent screen (sensitive scope OR silent-cap exceeded OR no prior grant)
 *   - RENDER_INCREMENTAL    show the incremental consent screen (only new non-sensitive scopes)
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Consent;

/**
 * Immutable consent-routing decision returned by {@see ConsentDecisionEvaluator}.
 */
final class ConsentDecision {

	public const AUTO_APPROVE       = 'auto_approve';
	public const RENDER_FULL        = 'render_full';
	public const RENDER_INCREMENTAL = 'render_incremental';

	/**
	 * @param string   $action        One of the ACTION_* constants.
	 * @param string[] $requested     The requested scope set (validated, deduplicated).
	 * @param string[] $previously    Scopes the user previously granted to this client.
	 * @param string[] $newly_added   Scopes in $requested not in $previously.
	 * @param string[] $sensitive     Scopes in $requested that are sensitive.
	 * @param string   $reason        Operator-facing rationale ("" when AUTO_APPROVE).
	 */
	public function __construct(
		public readonly string $action,
		public readonly array  $requested,
		public readonly array  $previously,
		public readonly array  $newly_added,
		public readonly array  $sensitive,
		public readonly string $reason = ''
	) {}

	/** True when the authorize endpoint should mint a code without rendering. */
	public function is_auto_approve(): bool {
		return self::AUTO_APPROVE === $this->action;
	}

	/** True when the authorize endpoint should render the full consent screen. */
	public function is_render_full(): bool {
		return self::RENDER_FULL === $this->action;
	}

	/** True when the authorize endpoint should render the incremental consent screen. */
	public function is_render_incremental(): bool {
		return self::RENDER_INCREMENTAL === $this->action;
	}
}
