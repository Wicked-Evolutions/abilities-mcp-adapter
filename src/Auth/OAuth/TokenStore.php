<?php
/**
 * OAuth token storage — access tokens, refresh tokens with family revocation.
 *
 * All tokens stored as SHA-256 hashes. Plaintext only in transit.
 * Refresh token family revocation + 30-second idempotent retry grace (H.2.1).
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

/**
 * Manages kl_oauth_tokens and kl_oauth_refresh_tokens tables.
 */
final class TokenStore {

	/** Grace window for idempotent refresh retry (seconds). */
	private const ROTATION_GRACE_SECONDS = 30;

	/** Access token TTL default (seconds). */
	public const ACCESS_TTL = 86400;

	/** Refresh token TTL default (seconds, rolling). */
	public const REFRESH_TTL = 7776000;

	private static function access_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'kl_oauth_tokens';
	}

	private static function refresh_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'kl_oauth_refresh_tokens';
	}

	/**
	 * Issue a new access + refresh token pair.
	 *
	 * The response always includes `token_type: Bearer` (RFC 6749 §5.1 REQUIRED)
	 * and the granted `scope` as stored (the expanded set, per RFC 6749 §3.3).
	 * Scope is always returned — the stored set is umbrella-expanded so it
	 * always differs from the umbrella strings the client originally requested.
	 *
	 * @param string      $client_id
	 * @param int         $user_id
	 * @param string      $scope       Space-separated scope string (umbrella-expanded).
	 * @param string      $resource    Resource indicator URL.
	 * @param int         $access_ttl  Override access TTL (seconds).
	 * @param int         $refresh_ttl Override refresh TTL (seconds).
	 * @param string|null $family_id   Existing family ID to inherit (rotation path).
	 *                                 Null generates a fresh family ID (initial issuance).
	 * @return array{access_token: string, token_type: string, refresh_token: string, expires_in: int, scope: string}
	 */
	public static function issue(
		string  $client_id,
		int     $user_id,
		string  $scope,
		string  $resource,
		int     $access_ttl  = self::ACCESS_TTL,
		int     $refresh_ttl = self::REFRESH_TTL,
		?string $family_id   = null
	): array {
		global $wpdb;

		$access_token  = bin2hex( random_bytes( 32 ) );
		$refresh_token = bin2hex( random_bytes( 32 ) );
		$access_hash   = hash( 'sha256', $access_token );
		$refresh_hash  = hash( 'sha256', $refresh_token );
		$family_id     = $family_id ?? bin2hex( random_bytes( 16 ) );
		$now           = gmdate( 'Y-m-d H:i:s' );

		// Apply operator TTL filters.
		$context = compact( 'client_id', 'user_id', 'resource' ) + [ 'scope' => explode( ' ', $scope ) ];
		$access_ttl  = (int) apply_filters( 'abilities_oauth_access_ttl', $access_ttl, $context );
		$refresh_ttl = (int) apply_filters( 'abilities_oauth_refresh_ttl', $refresh_ttl, $context );
		$min_ttl     = (int) apply_filters( 'abilities_oauth_min_grant_ttl', 300 );
		$max_ttl     = (int) apply_filters( 'abilities_oauth_max_grant_ttl', 7776000 );
		$access_ttl  = max( $min_ttl, min( $max_ttl, $access_ttl ) );

		$access_expires  = gmdate( 'Y-m-d H:i:s', time() + $access_ttl );
		$refresh_expires = gmdate( 'Y-m-d H:i:s', time() + $refresh_ttl );

		$wpdb->query( 'START TRANSACTION' );
		try {
			$wpdb->insert(
				self::access_table(),
				[
					'token_hash'  => $access_hash,
					'client_id'   => $client_id,
					'user_id'     => $user_id,
					'scope'       => $scope,
					'resource'    => $resource,
					'expires_at'  => $access_expires,
					'revoked'     => 0,
					'created_at'  => $now,
				],
				[ '%s', '%s', '%d', '%s', '%s', '%s', '%d', '%s' ]
			);
			$access_id = (int) $wpdb->insert_id;

			$wpdb->insert(
				self::refresh_table(),
				[
					'token_hash'      => $refresh_hash,
					'access_token_id' => $access_id,
					'client_id'       => $client_id,
					'user_id'         => $user_id,
					'scope'           => $scope,
					'resource'        => $resource,
					'family_id'       => $family_id,
					'expires_at'      => $refresh_expires,
					'revoked'         => 0,
					'created_at'      => $now,
				],
				[ '%s', '%d', '%s', '%d', '%s', '%s', '%s', '%s', '%d', '%s' ]
			);

			$wpdb->query( 'COMMIT' );
		} catch ( \Throwable $e ) {
			$wpdb->query( 'ROLLBACK' );
			throw $e;
		}

		return [
			'access_token'  => $access_token,
			'token_type'    => 'Bearer',
			'refresh_token' => $refresh_token,
			'expires_in'    => $access_ttl,
			'scope'         => $scope,
		];
	}

	/**
	 * Rotate a refresh token. Returns a new access+refresh pair.
	 *
	 * Implements family revocation and idempotent retry grace (H.2.1, C-2):
	 *
	 *   - Within ROTATION_GRACE_SECONDS of a successful rotation, a retry with
	 *     the same old refresh token returns the *same* plaintext pair issued
	 *     at rotation time. The pair is stored encrypted-at-rest under a key
	 *     derived from the old plaintext token (HKDF over AUTH_KEY); only a
	 *     client presenting the original token can decrypt. On successful
	 *     retry the blob is wiped (one-shot delivery).
	 *
	 *   - Outside the grace window, a retry is treated as replay: the entire
	 *     token family is revoked and the blob is wiped.
	 *
	 * @param string $refresh_token Plaintext refresh token.
	 * @param string $client_id     Must match stored client_id.
	 * @return array|null Token pair on success; null triggers invalid_grant.
	 */
	public static function rotate( string $refresh_token, string $client_id ): ?array {
		global $wpdb;

		$refresh_hash = hash( 'sha256', $refresh_token );

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM `' . self::refresh_table() . '` WHERE token_hash = %s AND client_id = %s',
				$refresh_hash,
				$client_id
			)
		);

		if ( ! $row ) {
			return null; // invalid_grant
		}

		if ( $row->revoked && is_null( $row->rotated_to_hash ) ) {
			// Explicitly revoked (not via rotation) — hard invalid_grant.
			return null;
		}

		if ( ! is_null( $row->rotated_at ) ) {
			// This token was already rotated.
			$rotated_at_ts = strtotime( $row->rotated_at . ' UTC' );
			$age           = time() - $rotated_at_ts;

			if ( $age <= self::ROTATION_GRACE_SECONDS ) {
				// Idempotent retry within grace window — decrypt and return the
				// original plaintext pair issued at rotation time.
				$pair = self::decrypt_replay_blob( $row, $refresh_token );
				if ( $pair === null ) {
					// Blob missing or decryption failed — pre-C-2 row, or row
					// already consumed by a prior retry. Fall through to invalid_grant.
					return null;
				}

				// One-shot delivery: wipe the blob so a subsequent retry within
				// the grace window cannot replay the same plaintext again.
				$wpdb->update(
					self::refresh_table(),
					[ 'replay_blob' => null, 'replay_blob_iv' => null ],
					[ 'token_hash' => $refresh_hash ],
					[ '%s', '%s' ],
					[ '%s' ]
				);

				return $pair;
			}

			// Replay detected outside grace — revoke entire family and wipe blob.
			self::revoke_family( $row->family_id );
			return null;
		}

		// Normal rotation path: token is valid, not yet rotated.
		if ( $row->revoked ) {
			return null;
		}

		// Check expiry.
		$expires = \DateTimeImmutable::createFromFormat( 'Y-m-d H:i:s', $row->expires_at, new \DateTimeZone( 'UTC' ) );
		if ( $expires < new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) ) ) {
			return null;
		}

		// Issue new pair — inherit family_id so replay detection covers the full chain (H.2.1).
		$new_pair = self::issue( $row->client_id, (int) $row->user_id, $row->scope, $row->resource, self::ACCESS_TTL, self::REFRESH_TTL, $row->family_id );
		$new_refresh_hash = hash( 'sha256', $new_pair['refresh_token'] );

		// Encrypt the plaintext pair under a key derived from the *old* refresh
		// token. Stored on the old row so a retry with the same old token can
		// decrypt it within the grace window.
		$encrypted = self::encrypt_replay_blob( $new_pair, $refresh_token );

		// Mark old refresh as rotated (atomic update with condition).
		$updated = $wpdb->update(
			self::refresh_table(),
			[
				'revoked'         => 1,
				'rotated_at'      => gmdate( 'Y-m-d H:i:s' ),
				'rotated_to_hash' => $new_refresh_hash,
				'replay_blob'     => $encrypted['ciphertext'],
				'replay_blob_iv'  => $encrypted['iv'],
			],
			[ 'token_hash' => $refresh_hash, 'revoked' => 0 ],
			[ '%d', '%s', '%s', '%s', '%s' ],
			[ '%s', '%d' ]
		);

		if ( ! $updated ) {
			// Race lost — another rotation beat us.
			return null;
		}

		return $new_pair;
	}

	/**
	 * Derive a 32-byte AES-256-GCM key from the old refresh token's plaintext.
	 *
	 * HKDF-SHA256 binds the key to (a) the plaintext of the old refresh token
	 * — supplied by the retrying client — and (b) AUTH_KEY, which is private to
	 * the WP installation. A DB exfiltrator without the original plaintext
	 * cannot decrypt the blob; the original plaintext is never persisted.
	 *
	 * If AUTH_KEY is not defined (e.g. test environment), an empty salt is used.
	 * The token plaintext alone still provides 256 bits of secret input.
	 */
	private static function replay_blob_key( string $old_refresh_plaintext ): string {
		$salt = defined( 'AUTH_KEY' ) ? (string) AUTH_KEY : '';
		return hash_hkdf( 'sha256', $old_refresh_plaintext, 32, 'oauth-replay-blob', $salt );
	}

	/**
	 * Encrypt the new token pair for grace-window replay.
	 *
	 * @param array  $pair                  The pair returned by issue().
	 * @param string $old_refresh_plaintext Used to derive the encryption key.
	 * @return array{ciphertext: string, iv: string}
	 */
	private static function encrypt_replay_blob( array $pair, string $old_refresh_plaintext ): array {
		$plaintext = json_encode( [
			'access_token'  => $pair['access_token'],
			'token_type'    => $pair['token_type'],
			'refresh_token' => $pair['refresh_token'],
			'expires_in'    => $pair['expires_in'],
			'scope'         => $pair['scope'],
		] );
		$key = self::replay_blob_key( $old_refresh_plaintext );
		$iv  = random_bytes( 12 );
		$tag = '';
		$ct  = openssl_encrypt( $plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
		// ciphertext is stored as ciphertext || tag; iv stored as hex.
		return [
			'ciphertext' => $ct . $tag,
			'iv'         => bin2hex( $iv ),
		];
	}

	/**
	 * Decrypt a stored replay blob using the supplied old refresh token plaintext.
	 *
	 * Returns the original token-pair array shape, or null if the blob is missing,
	 * malformed, or the supplied plaintext does not derive the correct key.
	 */
	private static function decrypt_replay_blob( object $row, string $old_refresh_plaintext ): ?array {
		if ( empty( $row->replay_blob ) || empty( $row->replay_blob_iv ) ) {
			return null;
		}
		$blob = (string) $row->replay_blob;
		if ( strlen( $blob ) < 16 ) {
			return null;
		}
		$tag = substr( $blob, -16 );
		$ct  = substr( $blob, 0, -16 );
		$iv  = @hex2bin( (string) $row->replay_blob_iv );
		if ( $iv === false || strlen( $iv ) !== 12 ) {
			return null;
		}
		$key = self::replay_blob_key( $old_refresh_plaintext );
		$pt  = openssl_decrypt( $ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
		if ( $pt === false ) {
			return null;
		}
		$decoded = json_decode( $pt, true );
		if ( ! is_array( $decoded ) || ! isset( $decoded['access_token'], $decoded['refresh_token'] ) ) {
			return null;
		}
		return $decoded;
	}

	/**
	 * Look up a bearer access token. Returns the DB row or null.
	 * MUST NOT be object-cached (H.1.2, H.2.7) — revocation is zero-latency.
	 *
	 * @param string $bearer_token Plaintext bearer token from Authorization header.
	 * @return object|null
	 */
	public static function lookup_access_token( string $bearer_token ): ?object {
		global $wpdb;

		$hash = hash( 'sha256', $bearer_token );

		// Direct DB query — intentionally bypasses object cache.
		// Cached stale "token is valid" answers are a security issue.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM `' . self::access_table() . '` WHERE token_hash = %s',
				$hash
			)
		);

		return $row ?: null;
	}

	/**
	 * Look up basic metadata (client_id, family_id, type) for a plaintext token.
	 *
	 * Returns an object with:
	 *   - client_id  string
	 *   - family_id  string|null  (null for access tokens)
	 *   - type       'access'|'refresh'
	 *
	 * Returns null when the token is not found in either table. Used by
	 * RevokeEndpoint to verify client ownership before revoking (H-2, RFC 7009 §2.1).
	 */
	public static function find_token_meta( string $token ): ?object {
		global $wpdb;
		$hash = hash( 'sha256', $token );

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT client_id, NULL AS family_id, \'access\' AS type FROM `' . self::access_table() . '` WHERE token_hash = %s',
				$hash
			)
		);
		if ( $row ) {
			return $row;
		}

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT client_id, family_id, \'refresh\' AS type FROM `' . self::refresh_table() . '` WHERE token_hash = %s',
				$hash
			)
		);
		return $row ?: null;
	}

	/**
	 * Revoke an access or refresh token by plaintext value.
	 *
	 * For refresh tokens, also cascades to revoke the entire family (H-2):
	 * revoking a refresh token must invalidate all access tokens in the family
	 * so the client cannot obtain new access tokens by replaying sibling refreshes.
	 *
	 * Idempotent — always returns true per RFC 7009.
	 */
	public static function revoke_by_plaintext( string $token ): void {
		global $wpdb;
		$hash = hash( 'sha256', $token );

		// Cascade: if this is a refresh token, revoke the whole family.
		$refresh_row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT family_id FROM `' . self::refresh_table() . '` WHERE token_hash = %s',
				$hash
			)
		);
		if ( $refresh_row && isset( $refresh_row->family_id ) ) {
			self::revoke_family( (string) $refresh_row->family_id );
			return;
		}

		// For access tokens: revoke the access token and its paired refresh token(s).
		$access_row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT id FROM `' . self::access_table() . '` WHERE token_hash = %s',
				$hash
			)
		);
		$wpdb->update( self::access_table(), [ 'revoked' => 1 ], [ 'token_hash' => $hash ], [ '%d' ], [ '%s' ] );
		if ( $access_row && isset( $access_row->id ) ) {
			$wpdb->update( self::refresh_table(), [ 'revoked' => 1 ], [ 'access_token_id' => (int) $access_row->id ], [ '%d' ], [ '%d' ] );
		}
	}

	/**
	 * Revoke all tokens in a refresh token family (H.2.1 — replay detection).
	 */
	public static function revoke_family( string $family_id ): void {
		global $wpdb;

		$wpdb->query( 'START TRANSACTION' );
		try {
			$wpdb->query(
				$wpdb->prepare(
					'UPDATE `' . self::refresh_table() . '` SET revoked = 1 WHERE family_id = %s',
					$family_id
				)
			);
			// Revoke access tokens linked to this family's refresh tokens.
			$wpdb->query(
				$wpdb->prepare(
					'UPDATE `' . self::access_table() . '` t
					 JOIN `' . self::refresh_table() . '` r ON r.access_token_id = t.id
					 SET t.revoked = 1
					 WHERE r.family_id = %s',
					$family_id
				)
			);
			$wpdb->query( 'COMMIT' );
		} catch ( \Throwable $e ) {
			$wpdb->query( 'ROLLBACK' );
		}
	}

	/** Update last_used_at for a token. Fire-and-forget — no error handling needed. */
	public static function touch( string $token_hash ): void {
		global $wpdb;
		$wpdb->update(
			self::access_table(),
			[ 'last_used_at' => gmdate( 'Y-m-d H:i:s' ) ],
			[ 'token_hash' => $token_hash ],
			[ '%s' ],
			[ '%s' ]
		);
	}
}
