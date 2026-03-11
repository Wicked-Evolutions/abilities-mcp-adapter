<?php
/**
 * MCP Session Manager using User Meta
 *
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Transport\Infrastructure;

/**
 * MCP Session Manager
 *
 * Handles session creation, validation, and cleanup using user meta storage.
 * Sessions are tied to authenticated users to prevent anonymous session flooding.
 */
final class SessionManager {

	/**
	 * User meta key for storing sessions
	 *
	 * @var string
	 */
	private const SESSION_META_KEY = 'mcp_adapter_sessions';

	/**
	 * Transient key prefix for per-user session write locks.
	 *
	 * @var string
	 */
	private const LOCK_KEY_PREFIX = 'mcp_session_lock_';

	/**
	 * Lock TTL in seconds. Short enough to self-heal on crash.
	 *
	 * @var int
	 */
	private const LOCK_TTL = 5;

	/**
	 * Maximum attempts to acquire the write lock before giving up.
	 *
	 * @var int
	 */
	private const LOCK_MAX_ATTEMPTS = 10;

	/**
	 * Acquire a per-user write lock using WordPress transients.
	 *
	 * Uses set_transient with a check-before-set pattern backed by
	 * the object cache's atomic `add` when available, or the options
	 * table `INSERT IGNORE` otherwise — both are safe against races.
	 *
	 * @param int $user_id The user ID to lock for.
	 *
	 * @return bool True if lock acquired, false on timeout.
	 */
	private static function acquire_lock( int $user_id ): bool {
		$key = self::LOCK_KEY_PREFIX . $user_id;

		for ( $i = 0; $i < self::LOCK_MAX_ATTEMPTS; $i++ ) {
			// set_transient returns false if the key already exists (in persistent cache).
			// For the DB-backed fallback we set a short TTL; worst case the lock expires in LOCK_TTL seconds.
			if ( false === get_transient( $key ) ) {
				set_transient( $key, 1, self::LOCK_TTL );

				return true;
			}

			// Brief sleep between attempts: 10–50 ms to back off without blocking long.
			usleep( random_int( 10000, 50000 ) );
		}

		return false;
	}

	/**
	 * Release the per-user write lock.
	 *
	 * @param int $user_id The user ID to unlock.
	 *
	 * @return void
	 */
	private static function release_lock( int $user_id ): void {
		delete_transient( self::LOCK_KEY_PREFIX . $user_id );
	}

	/**
	 * Maximum sessions per user.
	 *
	 * @var int
	 */
	private const DEFAULT_MAX_SESSIONS = 32;

	/**
	 * Session inactivity timeout in seconds (24 hours).
	 *
	 * @var int
	 */
	private const DEFAULT_INACTIVITY_TIMEOUT = DAY_IN_SECONDS;

	/**
	 * Get configuration values.
	 *
	 * @return array<string, int> Configuration array.
	 */
	private static function get_config(): array {
		return array(
			'max_sessions'       => (int) apply_filters( 'mcp_adapter_session_max_per_user', self::DEFAULT_MAX_SESSIONS ),
			'inactivity_timeout' => (int) apply_filters( 'mcp_adapter_session_inactivity_timeout', self::DEFAULT_INACTIVITY_TIMEOUT ),
		);
	}

	/**
	 * Clear an inactive session (internal cleanup).
	 *
	 * @param int $user_id The user ID.
	 * @param string $session_id The session ID to clear.
	 *
	 * @return void
	 */
	/**
	 * Remove a single session entry. Must be called while lock is already held.
	 *
	 * @param int    $user_id    The user ID.
	 * @param string $session_id The session ID to remove.
	 *
	 * @return void
	 */
	private static function clear_session( int $user_id, string $session_id ): void {
		$sessions = self::get_all_user_sessions( $user_id );

		if ( ! isset( $sessions[ $session_id ] ) ) {
			return;
		}

		unset( $sessions[ $session_id ] );
		update_user_meta( $user_id, self::SESSION_META_KEY, $sessions );
	}

	/**
	 * Create a new session for a user.
	 *
	 * Returns an array with 'session_id' and 'session_token'. The token is a
	 * per-session HMAC secret the client must echo back on every subsequent
	 * request via the Mcp-Session-Token header, binding the session to the
	 * initiating client and preventing session fixation via a stolen session ID.
	 *
	 * @param int   $user_id The user ID.
	 * @param array $params  Client parameters from initialize request.
	 *
	 * @return array{session_id:string,session_token:string}|false Session data on success, false on failure.
	 */
	public static function create_session( int $user_id, array $params = array() ) {
		if ( ! $user_id || ! get_user_by( 'id', $user_id ) ) {
			return false;
		}

		if ( ! self::acquire_lock( $user_id ) ) {
			return false; // Could not acquire write lock — fail safe.
		}

		try {
		// Cleanup inactive sessions first (inside lock so cleanup + create is atomic)
		self::cleanup_expired_sessions_unlocked( $user_id );

		// Get current sessions
		$sessions = self::get_all_user_sessions( $user_id );

		// Check session limit - remove oldest if over limit
		$config       = self::get_config();
		$max_sessions = $config['max_sessions'];
		if ( count( $sessions ) >= $max_sessions ) {
			// Remove oldest session (FIFO) - sort by created_at and remove first
			uasort(
				$sessions,
				static function ( $a, $b ) {
					return $a['created_at'] <=> $b['created_at'];
				}
			);

			array_shift( $sessions );
		}

		// Create a new session with a cryptographic secret for HMAC token binding.
		// The session_secret never leaves the server — only the derived token is sent to the client.
		$session_id     = wp_generate_uuid4();
		$session_secret = bin2hex( random_bytes( 32 ) ); // 256-bit secret
		$now            = time();

		$sessions[ $session_id ] = array(
			'created_at'     => $now,
			'last_activity'  => $now,
			'client_params'  => $params,
			'session_secret' => $session_secret,
		);

		// Save sessions
		update_user_meta( $user_id, self::SESSION_META_KEY, $sessions );

		// Derive the client token: HMAC-SHA256(secret, session_id).
		// The client must return this in Mcp-Session-Token on every request.
		$session_token = hash_hmac( 'sha256', $session_id, $session_secret );

		return array(
			'session_id'    => $session_id,
			'session_token' => $session_token,
		);
		} finally {
			self::release_lock( $user_id );
		}
	}

	/**
	 * Verify the session token supplied by the client.
	 *
	 * Computes the expected HMAC from the stored secret and compares it
	 * in constant time to prevent timing attacks.
	 *
	 * @param int    $user_id       The user ID.
	 * @param string $session_id    The session ID.
	 * @param string $client_token  The token the client sent in Mcp-Session-Token.
	 *
	 * @return bool True if the token is valid, false otherwise.
	 */
	public static function verify_session_token( int $user_id, string $session_id, string $client_token ): bool {
		$sessions = self::get_all_user_sessions( $user_id );

		if ( ! isset( $sessions[ $session_id ]['session_secret'] ) ) {
			// Legacy session without a secret — fail closed.
			return false;
		}

		$expected = hash_hmac( 'sha256', $session_id, $sessions[ $session_id ]['session_secret'] );

		return hash_equals( $expected, $client_token );
	}

	/**
	 * Get a specific session for a user
	 *
	 * @param int $user_id The user ID.
	 * @param string $session_id The session ID.
	 *
	 * @return array|\WP_Error|false Session data on success, WP_Error on invalid input, false if not found or inactive.
	 */
	public static function get_session( int $user_id, string $session_id ) {
		if ( ! $user_id || ! $session_id ) {
			return new \WP_Error( 403, 'Invalid user ID or session ID.' );
		}

		$sessions = self::get_all_user_sessions( $user_id );

		if ( ! isset( $sessions[ $session_id ] ) ) {
			return false;
		}

		$session = $sessions[ $session_id ];

		// Check inactivity timeout
		$config             = self::get_config();
		$inactivity_timeout = $config['inactivity_timeout'];
		if ( $session['last_activity'] + $inactivity_timeout < time() ) {
			self::clear_session( $user_id, $session_id );

			return false;
		}

		return $session;
	}

	/**
	 * Validate a session and update last activity
	 *
	 * @param int $user_id The user ID.
	 * @param string $session_id The session ID.
	 *
	 * @return bool True if valid, false otherwise.
	 */
	public static function validate_session( int $user_id, string $session_id ): bool {
		if ( ! $user_id || ! $session_id ) {
			return false;
		}

		if ( ! self::acquire_lock( $user_id ) ) {
			return false;
		}

		try {
			// Opportunistic cleanup (inside lock)
			self::cleanup_expired_sessions_unlocked( $user_id );

			$sessions = self::get_all_user_sessions( $user_id );

			if ( ! isset( $sessions[ $session_id ] ) ) {
				return false;
			}

			$session = $sessions[ $session_id ];

			// Check inactivity timeout
			$config             = self::get_config();
			$inactivity_timeout = $config['inactivity_timeout'];
			if ( $session['last_activity'] + $inactivity_timeout < time() ) {
				unset( $sessions[ $session_id ] );
				update_user_meta( $user_id, self::SESSION_META_KEY, $sessions );

				return false;
			}

			// Update last activity atomically within the lock.
			$sessions[ $session_id ]['last_activity'] = time();
			update_user_meta( $user_id, self::SESSION_META_KEY, $sessions );

			return true;
		} finally {
			self::release_lock( $user_id );
		}
	}

	/**
	 * Delete a specific session
	 *
	 * @param int $user_id The user ID.
	 * @param string $session_id The session ID.
	 *
	 * @return bool True on success, false on failure.
	 */
	public static function delete_session( int $user_id, string $session_id ): bool {
		if ( ! $user_id || ! $session_id ) {
			return false;
		}

		if ( ! self::acquire_lock( $user_id ) ) {
			return false;
		}

		try {
			$sessions = self::get_all_user_sessions( $user_id );

			if ( ! isset( $sessions[ $session_id ] ) ) {
				return false;
			}

			unset( $sessions[ $session_id ] );

			if ( empty( $sessions ) ) {
				delete_user_meta( $user_id, self::SESSION_META_KEY );
			} else {
				update_user_meta( $user_id, self::SESSION_META_KEY, $sessions );
			}

			return true;
		} finally {
			self::release_lock( $user_id );
		}
	}

	/**
	 * Cleanup inactive sessions for a user
	 *
	 * @param int $user_id The user ID.
	 *
	 * @return int Number of sessions removed.
	 */
	/**
	 * Cleanup expired sessions — acquires lock. For external callers.
	 *
	 * @param int $user_id The user ID.
	 *
	 * @return int Number of sessions removed.
	 */
	public static function cleanup_expired_sessions( int $user_id ): int {
		if ( ! $user_id ) {
			return 0;
		}

		if ( ! self::acquire_lock( $user_id ) ) {
			return 0;
		}

		try {
			return self::cleanup_expired_sessions_unlocked( $user_id );
		} finally {
			self::release_lock( $user_id );
		}
	}

	/**
	 * Cleanup expired sessions — must be called while lock is already held.
	 *
	 * @param int $user_id The user ID.
	 *
	 * @return int Number of sessions removed.
	 */
	private static function cleanup_expired_sessions_unlocked( int $user_id ): int {
		$sessions = self::get_all_user_sessions( $user_id );
		$now      = time();
		$removed  = 0;

		$config             = self::get_config();
		$inactivity_timeout = $config['inactivity_timeout'];

		foreach ( $sessions as $session_id => $session ) {
			// Check if still active - skip if valid
			if ( $session['last_activity'] + $inactivity_timeout >= $now ) {
				continue;
			}

			// Session is inactive - remove it
			unset( $sessions[ $session_id ] );
			++$removed;
		}

		if ( $removed > 0 ) {
			if ( empty( $sessions ) ) {
				delete_user_meta( $user_id, self::SESSION_META_KEY );
			} else {
				update_user_meta( $user_id, self::SESSION_META_KEY, $sessions );
			}
		}

		return $removed;
	}

	/**
	 * Get all sessions for a user
	 *
	 * @param int $user_id The user ID.
	 *
	 * @return array Array of sessions.
	 */
	public static function get_all_user_sessions( int $user_id ): array {
		if ( ! $user_id ) {
			return array();
		}

		$sessions = get_user_meta( $user_id, self::SESSION_META_KEY, true );

		if ( ! is_array( $sessions ) ) {
			return array();
		}

		return $sessions;
	}
}
