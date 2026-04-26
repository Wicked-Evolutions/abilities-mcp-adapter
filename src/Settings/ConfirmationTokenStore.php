<?php
/**
 * In-chat 1/2 confirmation token store.
 *
 * Mints a one-time token bound to (session, ability, params hash). The
 * token is stored as a WP transient with ~60s TTL; consume_token() deletes
 * it on first valid use. Tokens are NOT proof of human consent — a malicious
 * AI client could synthesise a "1" reply. They prevent accidental weakening.
 *
 * Cryptographic-trust paths (Bucket 2, master toggle off) intentionally bypass
 * this mechanism and require the Admin UI checkbox.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Settings;

/**
 * Mint and consume confirmation tokens for safety-weakening abilities.
 */
final class ConfirmationTokenStore {

	public const TRANSIENT_PREFIX = 'abilities_mcp_confirm_';
	public const TTL_SECONDS      = 60;

	/**
	 * Mint a new token bound to (session, ability, params).
	 *
	 * Returns the opaque token string. Stored payload includes the binding
	 * tuple so consume_token() can re-verify the call shape on redemption.
	 *
	 * @param string $session_id  Stable session identifier (MCP session, falls back to user+ip).
	 * @param string $ability     Ability name being weakened.
	 * @param array  $params      Sanitized scalar params (canonicalised before hashing).
	 *
	 * @return string The token.
	 */
	public static function mint( string $session_id, string $ability, array $params ): string {
		$token = wp_generate_password( 32, false, false );

		$payload = array(
			'session_id'  => $session_id,
			'ability'     => $ability,
			'params_hash' => self::params_hash( $params ),
			'created_at'  => time(),
		);

		set_transient( self::TRANSIENT_PREFIX . $token, $payload, self::TTL_SECONDS );

		return $token;
	}

	/**
	 * Consume a token. Returns true on a valid+matching one-time redemption,
	 * \WP_Error otherwise. Always deletes the transient on lookup so a token
	 * cannot be replayed.
	 *
	 * Returns specific error codes so callers can log fine-grained reasons:
	 *   - missing_token        — no token presented
	 *   - token_unknown        — transient expired or never minted
	 *   - session_mismatch     — token bound to different session
	 *   - ability_mismatch     — token minted for a different ability
	 *   - params_mismatch      — same ability but different parameters
	 *
	 * @param string|null $token
	 * @param string      $session_id
	 * @param string      $ability
	 * @param array       $params
	 *
	 * @return true|\WP_Error
	 */
	public static function consume( ?string $token, string $session_id, string $ability, array $params ) {
		if ( ! is_string( $token ) || '' === $token ) {
			return new \WP_Error( 'missing_token', 'No confirmation token presented.' );
		}

		$key     = self::TRANSIENT_PREFIX . $token;
		$payload = get_transient( $key );

		// Always invalidate on any lookup attempt — one-time only.
		delete_transient( $key );

		if ( ! is_array( $payload ) ) {
			return new \WP_Error( 'token_unknown', 'Confirmation token is unknown or has expired.' );
		}

		if ( ( $payload['session_id'] ?? '' ) !== $session_id ) {
			return new \WP_Error( 'session_mismatch', 'Confirmation token belongs to a different session.' );
		}
		if ( ( $payload['ability'] ?? '' ) !== $ability ) {
			return new \WP_Error( 'ability_mismatch', 'Confirmation token was minted for a different ability.' );
		}
		if ( ( $payload['params_hash'] ?? '' ) !== self::params_hash( $params ) ) {
			return new \WP_Error( 'params_mismatch', 'Confirmation token does not match the call parameters.' );
		}

		return true;
	}

	/**
	 * Best-effort session identifier used to bind tokens.
	 *
	 * MCP transports may set `Mcp-Session-Id`; if absent we fall back to
	 * (user_id|ip) so a fresh user has a stable enough binding for the
	 * 60-second window.
	 */
	public static function current_session_id(): string {
		$header = isset( $_SERVER['HTTP_MCP_SESSION_ID'] ) ? (string) $_SERVER['HTTP_MCP_SESSION_ID'] : '';
		if ( '' !== $header ) {
			return substr( preg_replace( '/[^a-zA-Z0-9_\-]/', '', $header ) ?? '', 0, 64 );
		}

		$user_id = function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0;
		$ip      = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		return 'fallback-' . $user_id . '-' . substr( md5( $ip ), 0, 16 );
	}

	/**
	 * Stable hash of the canonicalised params array.
	 */
	private static function params_hash( array $params ): string {
		// Lower-case keys + json-encode with sorted keys for determinism.
		$normalised = array();
		foreach ( $params as $k => $v ) {
			$normalised[ strtolower( (string) $k ) ] = is_string( $v ) ? trim( $v ) : $v;
		}
		ksort( $normalised );
		$json = wp_json_encode( $normalised );
		return hash( 'sha256', $json !== false ? $json : '' );
	}
}
