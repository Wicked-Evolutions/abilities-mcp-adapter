<?php
/**
 * Authorization code storage — short-lived, single-use codes with PKCE.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

/**
 * Manages kl_oauth_codes table.
 */
final class AuthorizationCodeStore {

	private static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'kl_oauth_codes';
	}

	/**
	 * Store a new authorization code.
	 *
	 * @param string $code_hash          SHA-256 hash of the plaintext code.
	 * @param string $client_id
	 * @param int    $user_id
	 * @param string $redirect_uri       Exact URI to bind for token exchange.
	 * @param string $scope              Space-separated scope string.
	 * @param string $resource           Resource indicator URL.
	 * @param string $code_challenge     PKCE S256 challenge.
	 * @param int    $ttl_seconds        Default 600 (10 minutes).
	 */
	public static function store(
		string $code_hash,
		string $client_id,
		int    $user_id,
		string $redirect_uri,
		string $scope,
		string $resource,
		string $code_challenge,
		int    $ttl_seconds = 600
	): void {
		global $wpdb;

		$wpdb->insert(
			self::table(),
			[
				'code_hash'            => $code_hash,
				'client_id'            => $client_id,
				'user_id'              => $user_id,
				'redirect_uri'         => $redirect_uri,
				'scope'                => $scope,
				'resource'             => $resource,
				'code_challenge'       => $code_challenge,
				'code_challenge_method'=> 'S256',
				'expires_at'           => gmdate( 'Y-m-d H:i:s', time() + $ttl_seconds ),
				'used'                 => 0,
				'created_at'           => gmdate( 'Y-m-d H:i:s' ),
			],
			[ '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' ]
		);
	}

	/**
	 * Consume an authorization code atomically.
	 *
	 * Verifies: not expired, not used, client_id matches, redirect_uri matches, PKCE S256.
	 * Uses UPDATE...WHERE used=0 for atomic single-use enforcement.
	 *
	 * @param string $code          Plaintext authorization code.
	 * @param string $client_id     Must match stored client_id.
	 * @param string $redirect_uri  Must match stored redirect_uri exactly.
	 * @param string $code_verifier PKCE verifier.
	 * @return object|null Code row on success, null on any verification failure.
	 */
	public static function consume(
		string $code,
		string $client_id,
		string $redirect_uri,
		string $code_verifier
	): ?object {
		global $wpdb;

		$code_hash = hash( 'sha256', $code );

		// Fetch the code row first (read; no write yet).
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM `' . self::table() . '`
				 WHERE code_hash = %s
				   AND used = 0
				   AND expires_at > UTC_TIMESTAMP()',
				$code_hash
			)
		);

		if ( ! $row ) {
			return null; // Not found, expired, or already used.
		}

		// client_id binding (H.1.1) — timing-safe.
		if ( ! hash_equals( $row->client_id, $client_id ) ) {
			return null;
		}

		// redirect_uri binding (H.1.1) — timing-safe.
		if ( ! hash_equals( $row->redirect_uri, $redirect_uri ) ) {
			return null;
		}

		// PKCE S256 verification (Appendix D.1 — lifted verbatim from StifLi).
		$computed_challenge = rtrim( strtr( base64_encode( hash( 'sha256', $code_verifier, true ) ), '+/', '-_' ), '=' );
		if ( ! hash_equals( $row->code_challenge, $computed_challenge ) ) {
			return null;
		}

		// Atomic mark-as-used: UPDATE...WHERE used=0. rows_affected = 0 means a race lost.
		$rows_affected = $wpdb->update(
			self::table(),
			[ 'used' => 1 ],
			[ 'code_hash' => $code_hash, 'used' => 0 ],
			[ '%d' ],
			[ '%s', '%d' ]
		);

		if ( ! $rows_affected ) {
			return null; // Race lost.
		}

		return $row;
	}

	/**
	 * Compute a PKCE S256 challenge from a plaintext verifier.
	 * Used by tests; production bridge does this client-side.
	 */
	public static function compute_challenge( string $verifier ): string {
		return rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );
	}
}
