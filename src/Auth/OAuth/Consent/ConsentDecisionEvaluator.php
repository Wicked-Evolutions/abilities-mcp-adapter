<?php
/**
 * Decide whether an /oauth/authorize request can auto-approve, must show
 * the full consent screen, or can show the incremental consent screen.
 *
 * Pure logic — all temporal + DB inputs are passed in by the caller (the
 * authorize endpoint). That keeps the decision unit-testable without DB or
 * clock fixtures.
 *
 * Decision contract (binding sources only):
 *   - Sub-issue #32: "Auto-approve logic: recognized client_id + unchanged
 *     non-sensitive scopes + within consent_max_silent_days"
 *   - Appendix H.2.4: any silence > consent_max_silent_days → FULL consent
 *   - Appendix H.3.4: sensitive scopes always show consent, even when
 *     previously granted; any new scope → consent (full if any sensitive,
 *     incremental if all new are non-sensitive)
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Consent;

use WickedEvolutions\McpAdapter\Auth\OAuth\ScopeRegistry;

/**
 * Pure-function decision engine for the authorize endpoint.
 */
final class ConsentDecisionEvaluator {

	/**
	 * Decide consent routing for a fully-validated authorize request.
	 *
	 * @param string[] $requested_scopes        Scopes from the authorize query, deduplicated, all known.
	 * @param string[] $previously_granted      Most recent active token's scope set; empty array if no prior grant.
	 * @param int|null $last_interactive_unix   UNIX timestamp of the last interactive consent for this (client, user); null if none.
	 * @param int      $now_unix                Current UNIX time (injected for testability).
	 * @param int      $consent_max_silent_days Resolved silent-cap from {@see PolicyStore}.
	 * @return ConsentDecision
	 */
	public static function evaluate(
		array $requested_scopes,
		array $previously_granted,
		?int  $last_interactive_unix,
		int   $now_unix,
		int   $consent_max_silent_days
	): ConsentDecision {
		$requested  = self::normalize( $requested_scopes );
		$previously = self::normalize( $previously_granted );

		$sensitive   = array_values( array_filter( $requested, [ ScopeRegistry::class, 'is_sensitive' ] ) );
		$newly_added = array_values( array_diff( $requested, $previously ) );

		// (1) No prior grant → full consent. The bridge has never authorized for this user.
		if ( null === $last_interactive_unix ) {
			return new ConsentDecision(
				ConsentDecision::RENDER_FULL,
				$requested,
				$previously,
				$newly_added,
				$sensitive,
				'first_authorization'
			);
		}

		// (2) Silent cap exceeded (Appendix H.2.4) → full consent regardless of scope set.
		$silent_seconds = $now_unix - $last_interactive_unix;
		$cap_seconds    = $consent_max_silent_days * 86400;
		if ( $silent_seconds > $cap_seconds ) {
			return new ConsentDecision(
				ConsentDecision::RENDER_FULL,
				$requested,
				$previously,
				$newly_added,
				$sensitive,
				'silent_cap_exceeded'
			);
		}

		// (3) Any sensitive scope in the request set (Appendix H.3.4) → full consent,
		//     even if every sensitive scope was previously granted.
		if ( ! empty( $sensitive ) ) {
			return new ConsentDecision(
				ConsentDecision::RENDER_FULL,
				$requested,
				$previously,
				$newly_added,
				$sensitive,
				'sensitive_scope_requested'
			);
		}

		// (4) Some non-sensitive scopes are new → incremental consent.
		if ( ! empty( $newly_added ) ) {
			return new ConsentDecision(
				ConsentDecision::RENDER_INCREMENTAL,
				$requested,
				$previously,
				$newly_added,
				$sensitive,
				'new_non_sensitive_scopes'
			);
		}

		// (5) Recognized client + unchanged non-sensitive scopes + within silent cap → auto-approve.
		return new ConsentDecision(
			ConsentDecision::AUTO_APPROVE,
			$requested,
			$previously,
			$newly_added,
			$sensitive
		);
	}

	/** Sort + deduplicate to keep set comparisons deterministic. */
	private static function normalize( array $scopes ): array {
		$clean = array_values( array_unique( array_filter( $scopes, 'is_string' ) ) );
		sort( $clean );
		return $clean;
	}
}
