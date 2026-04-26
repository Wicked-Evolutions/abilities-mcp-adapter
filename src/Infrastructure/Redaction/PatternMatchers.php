<?php
/**
 * Bucket 1 / Bucket 2 pattern matchers.
 *
 * All matchers operate on a single scalar string value. They MUST NOT be applied to
 * arrays, objects, numbers, booleans, or full JSON blobs — pattern matching across
 * free-form text would corrupt legitimate content (e.g. a blog post mentioning a
 * credit-card pattern).
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Infrastructure\Redaction;

/**
 * Scalar-string pattern matchers for Bucket 1 (secrets) and Bucket 2 (payment).
 */
final class PatternMatchers {

	/**
	 * Known password-hash format prefixes / markers.
	 *
	 * @var string[]
	 */
	private const PASSWORD_HASH_PREFIXES = array(
		'$P$',
		'$H$',
		'$2a$',
		'$2b$',
		'$2y$',
		'$argon2',
		'$pbkdf2',
		'$scrypt',
	);

	/**
	 * Known API-key value prefixes.
	 *
	 * @var string[]
	 */
	private const API_KEY_PREFIXES = array(
		'sk_live_',
		'sk_test_',
		'pk_live_',
		'pk_test_',
		'xoxb-',
		'xoxp-',
		'ghp_',
		'gho_',
		'ghu_',
		'ghs_',
		'ghr_',
	);

	/**
	 * Whether the value matches a known password-hash format.
	 *
	 * @param mixed $value Value to test.
	 * @return bool
	 */
	public static function is_password_hash( $value ): bool {
		if ( ! is_string( $value ) || '' === $value ) {
			return false;
		}
		foreach ( self::PASSWORD_HASH_PREFIXES as $prefix ) {
			if ( 0 === strpos( $value, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether the value matches a known API-key prefix or vendor pattern.
	 *
	 * Includes Stripe (sk_live_/sk_test_/pk_live_/pk_test_), Slack (xoxb-/xoxp-),
	 * GitHub (ghp_/gho_/ghu_/ghs_/ghr_), AWS access key id (AKIA + 16 upper alnum),
	 * Google API keys (AIza + 35 url-safe).
	 *
	 * @param mixed $value Value to test.
	 * @return bool
	 */
	public static function is_known_api_key( $value ): bool {
		if ( ! is_string( $value ) || '' === $value ) {
			return false;
		}

		foreach ( self::API_KEY_PREFIXES as $prefix ) {
			if ( 0 === strpos( $value, $prefix ) ) {
				return true;
			}
		}

		// AWS access key id: AKIA followed by 16 upper-case alphanumerics.
		if ( 1 === preg_match( '/^AKIA[0-9A-Z]{16}$/', $value ) ) {
			return true;
		}

		// Google API key: AIza followed by 35 url-safe characters.
		if ( 1 === preg_match( '/^AIza[0-9A-Za-z_\-]{35}$/', $value ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Whether the string is a 13-19 digit run that passes the Luhn check.
	 *
	 * Whitespace and hyphens between digit groups are not stripped — the matcher
	 * fires only when the value is *exactly* a contiguous digit string of plausible
	 * card length. This keeps blog-post text containing the literal word
	 * "1234-5678-9012-3456" out of scope (which is what we want; pattern matching
	 * is only meaningful on field values that actually look like a stored PAN).
	 *
	 * @param mixed $value Value to test.
	 * @return bool
	 */
	public static function passes_luhn( $value ): bool {
		if ( ! is_string( $value ) || 1 !== preg_match( '/^[0-9]{13,19}$/', $value ) ) {
			return false;
		}

		$sum     = 0;
		$flip    = false;
		$length  = strlen( $value );
		for ( $i = $length - 1; $i >= 0; $i-- ) {
			$digit = (int) $value[ $i ];
			if ( $flip ) {
				$digit *= 2;
				if ( $digit > 9 ) {
					$digit -= 9;
				}
			}
			$sum  += $digit;
			$flip  = ! $flip;
		}

		return 0 === ( $sum % 10 );
	}
}
