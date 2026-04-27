<?php
/**
 * Look up the timestamp of the last interactive consent for a (client_id,
 * user_id) pair. Drives the Appendix H.2.4 silent-cap check.
 *
 * Source of truth: the boundary log (`mcp_adapter_boundary_event` action).
 * Phase 1's logging contract emits one event per OAuth lifecycle step; we
 * emit two distinct event names so an interactive grant can be told apart
 * from an auto-approved one without inventing a new boundary tag:
 *
 *   - boundary.oauth_authorization_granted        — interactive consent
 *   - boundary.oauth_authorization_auto_approved  — silent re-auth
 *
 * H.2.4 explicitly requires "the most recent INTERACTIVE consent ... NOT
 * auto-approve," which is what makes the two-event-name split necessary.
 *
 * The actual read path is implementation-detail: most installs don't ship a
 * persistent boundary log table. Phase 3 records the last-interactive
 * timestamp directly via a per-(client,user) WP option as a side-effect of
 * the granted event, keyed so it's compact and bounded by client count.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Consent;

/**
 * Read + record the most recent interactive consent timestamp.
 */
final class LastConsentLookup {

	/** Option name prefix. Suffix = sha256(client_id|user_id). Bounded by client count. */
	private const OPTION_PREFIX = 'abilities_oauth_last_consent_';

	/** Compose the per-pair option name. */
	private static function key( string $client_id, int $user_id ): string {
		// sha1 keeps the option name well under WP's 191-char index cap and is
		// sufficient — this is a key, not a security primitive.
		return self::OPTION_PREFIX . sha1( $client_id . '|' . $user_id );
	}

	/**
	 * Most recent interactive-consent UNIX timestamp, or null if none recorded.
	 */
	public static function timestamp_for( string $client_id, int $user_id ): ?int {
		$value = get_option( self::key( $client_id, $user_id ), null );
		if ( null === $value || '' === $value ) {
			return null;
		}
		return (int) $value;
	}

	/**
	 * Record an interactive consent timestamp.
	 *
	 * Only call from the POST handler when the operator clicked Authorize.
	 * Auto-approve MUST NOT call this — that's what H.2.4 explicitly excludes.
	 */
	public static function record( string $client_id, int $user_id, int $now_unix ): void {
		update_option( self::key( $client_id, $user_id ), $now_unix );
	}

	/**
	 * Days elapsed since the last interactive consent, or null if never.
	 */
	public static function days_since( string $client_id, int $user_id, int $now_unix ): ?int {
		$ts = self::timestamp_for( $client_id, $user_id );
		if ( null === $ts ) {
			return null;
		}
		$delta = $now_unix - $ts;
		if ( $delta < 0 ) {
			return 0;
		}
		return (int) floor( $delta / 86400 );
	}
}
