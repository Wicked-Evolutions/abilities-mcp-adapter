<?php
/**
 * Per-site OAuth consent policy storage.
 *
 * Phase 3 introduces one policy field: `consent_max_silent_days` (Appendix
 * H.2.4 — long-lived auto-approve cap). Default 365 days. Operator-overridable
 * either via WP option (admin UI) or via the `abilities_oauth_consent_max_silent_days`
 * filter, mirroring the option+filter pattern Phase 1 uses for TTL knobs.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Consent;

/**
 * Read consent policy values with sane defaults and filter overrides.
 */
final class PolicyStore {

	/** WP option name for the silent-cap override. */
	public const OPTION_SILENT_DAYS = 'abilities_oauth_consent_max_silent_days';

	/** Default silent cap per Appendix H.2.4. */
	public const DEFAULT_SILENT_DAYS = 365;

	/** Hard floor — re-prompts more than once a day are operator hostile. */
	public const MIN_SILENT_DAYS = 1;

	/** Hard ceiling — beyond two years a re-confirmation is mandatory. */
	public const MAX_SILENT_DAYS = 730;

	/**
	 * Resolve the silent-cap in days.
	 *
	 * Resolution order:
	 *   1. Filter override (`abilities_oauth_consent_max_silent_days`) — wins if non-empty integer.
	 *   2. WP option (admin-set).
	 *   3. {@see DEFAULT_SILENT_DAYS}.
	 *
	 * The result is clamped to [MIN_SILENT_DAYS, MAX_SILENT_DAYS].
	 */
	public static function consent_max_silent_days(): int {
		$option = (int) get_option( self::OPTION_SILENT_DAYS, self::DEFAULT_SILENT_DAYS );
		if ( $option <= 0 ) {
			$option = self::DEFAULT_SILENT_DAYS;
		}

		$filtered = (int) apply_filters( self::OPTION_SILENT_DAYS, $option );
		if ( $filtered <= 0 ) {
			$filtered = $option;
		}

		return self::clamp( $filtered );
	}

	/** Clamp a candidate value to the supported range. */
	public static function clamp( int $days ): int {
		if ( $days < self::MIN_SILENT_DAYS ) {
			return self::MIN_SILENT_DAYS;
		}
		if ( $days > self::MAX_SILENT_DAYS ) {
			return self::MAX_SILENT_DAYS;
		}
		return $days;
	}
}
