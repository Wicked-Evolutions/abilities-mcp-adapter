<?php
/**
 * Redaction configuration — default keyword lists, options, and exemptions.
 *
 * Three buckets:
 *   - Bucket 1 (secrets): always-on, never disabled. Cannot be configured.
 *   - Bucket 2 (payment / regulated IDs): default-on, configurable via Admin UI only.
 *   - Bucket 3 (contact PII / access labels): default-on, configurable via Admin UI or AI.
 *
 * The custom keyword option `abilities_mcp_redaction_keywords` is a Bucket 3 extension list
 * (additional contact-style fields the operator wants redacted). Bucket 1 and Bucket 2
 * keyword lists are hard-coded — operators tune behaviour via exemptions, not list edits.
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
 * Redaction configuration loader.
 */
final class RedactionConfig {

	public const OPTION_MASTER_ENABLED      = 'abilities_mcp_redaction_master_enabled';
	public const OPTION_BUCKET3_KEYWORDS    = 'abilities_mcp_redaction_keywords';
	public const OPTION_BUCKET3_EXEMPTIONS  = 'abilities_mcp_bucket3_exemptions';
	public const OPTION_BUCKET2_EXEMPTIONS  = 'abilities_mcp_bucket2_exemptions';

	public const BUCKET_SECRETS  = 1;
	public const BUCKET_PAYMENT  = 2;
	public const BUCKET_CONTACT  = 3;

	/**
	 * Bucket 1 — always-on secrets.
	 *
	 * @return string[]
	 */
	public static function bucket1_keywords(): array {
		return array(
			// Credentials.
			'password',
			'pass',
			'passwd',
			'user_pass',
			'user_password',
			'db_password',
			'database_password',
			'smtp_password',
			'imap_password',
			'pop_password',
			'ftp_password',
			'ssh_password',

			// Named API keys / secrets.
			'api_key',
			'api_secret',
			'consumer_key',
			'consumer_secret',
			'client_secret',
			'client_key',
			'private_key',
			'license_key',
			'serial_key',
			'activation_key',
			'app_key',
			'app_secret',
			'webhook_secret',
			'webhook_key',
			'signing_key',
			'encryption_key',
			'master_key',
			'secret_key',

			// Tokens.
			'access_token',
			'refresh_token',
			'bearer_token',
			'auth_token',
			'authentication_token',
			'oauth_token',
			'oauth_secret',
			'session_token',
			'session_tokens',
			'session_secret',
			'csrf_token',
			'nonce_token',
			'id_token',
			'personal_access_token',

			// wp-config secrets.
			'auth_key',
			'secure_auth_key',
			'logged_in_key',
			'nonce_key',
			'auth_salt',
			'secure_auth_salt',
			'logged_in_salt',
			'nonce_salt',
		);
	}

	/**
	 * Bucket 2 — payment + regulated IDs.
	 *
	 * @return string[]
	 */
	public static function bucket2_keywords(): array {
		return array(
			'card_number',
			'cardnumber',
			'cc_number',
			'pan',
			'cvv',
			'cvc',
			'cv2',
			'card_cvv',
			'card_cvc',
			'card_pin',
			'ssn',
			'social_security_number',
			'social_security',
			'tax_id',
			'ein',
			'tin',
			'vat_number',
			'vat_id',
		);
	}

	/**
	 * Bucket 3 — contact PII / access labels (default list before custom additions).
	 *
	 * @return string[]
	 */
	public static function bucket3_default_keywords(): array {
		return array(
			// Email.
			'email',
			'user_email',
			'customer_email',
			'contact_email',
			'billing_email',
			'shipping_email',
			'payment_email',

			// Phone.
			'phone',
			'phone_number',
			'mobile',
			'mobile_number',
			'tel',
			'telephone',
			'billing_phone',
			'shipping_phone',
			'contact_phone',

			// Address.
			'address',
			'street_address',
			'address_line_1',
			'address_line_2',
			'street',
			'street1',
			'street2',
			'billing_address',
			'shipping_address',
			'billing_address_1',
			'shipping_address_1',

			// Login identity.
			'user_login',
			'username',

			// IP.
			'ip',
			'ip_address',
			'user_ip',
			'client_ip',
			'remote_ip',
			'last_ip',

			// Date of birth.
			'birthdate',
			'birth_date',
			'date_of_birth',
			'dob',

			// Public key (infrastructure, configurable per principle).
			'public_key',
		);
	}

	/**
	 * Whether Bucket 2 + Bucket 3 redaction is active.
	 *
	 * Bucket 1 ignores this toggle entirely.
	 *
	 * @return bool
	 */
	public static function is_master_enabled(): bool {
		$raw = function_exists( 'get_option' )
			? get_option( self::OPTION_MASTER_ENABLED, true )
			: true;

		$enabled = (bool) $raw;

		if ( function_exists( 'apply_filters' ) ) {
			$enabled = (bool) apply_filters( self::OPTION_MASTER_ENABLED, $enabled );
		}

		return $enabled;
	}

	/**
	 * Active Bucket 3 keyword list (defaults + custom additions, after filter).
	 *
	 * @return string[] Lower-cased canonical names.
	 */
	public static function bucket3_keywords(): array {
		$defaults = self::bucket3_default_keywords();
		$custom   = array();

		if ( function_exists( 'get_option' ) ) {
			$stored = get_option( self::OPTION_BUCKET3_KEYWORDS, array() );
			if ( is_array( $stored ) ) {
				foreach ( $stored as $kw ) {
					if ( is_string( $kw ) && '' !== $kw ) {
						$custom[] = $kw;
					}
				}
			}
		}

		$merged = array_merge( $defaults, $custom );

		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::OPTION_BUCKET3_KEYWORDS, $merged );
			if ( is_array( $filtered ) ) {
				$merged = array();
				foreach ( $filtered as $kw ) {
					if ( is_string( $kw ) && '' !== $kw ) {
						$merged[] = $kw;
					}
				}
			}
		}

		return self::normalize_keywords( $merged );
	}

	/**
	 * Whether the named ability is exempt from the given bucket.
	 *
	 * Bucket 1 is never exempt.
	 *
	 * @param string|null $ability_name Ability name (e.g. `fluent-cart/list-customers`), or null.
	 * @param int         $bucket       Bucket constant.
	 *
	 * @return bool
	 */
	public static function is_ability_exempt( ?string $ability_name, int $bucket ): bool {
		if ( self::BUCKET_SECRETS === $bucket || null === $ability_name || '' === $ability_name ) {
			return false;
		}

		$option = self::BUCKET_PAYMENT === $bucket
			? self::OPTION_BUCKET2_EXEMPTIONS
			: self::OPTION_BUCKET3_EXEMPTIONS;

		if ( ! function_exists( 'get_option' ) ) {
			return false;
		}

		$exempt = get_option( $option, array() );
		if ( ! is_array( $exempt ) ) {
			return false;
		}

		foreach ( $exempt as $name ) {
			if ( is_string( $name ) && $name === $ability_name ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Lower-case + dedupe a keyword list for case-insensitive matching.
	 *
	 * @param string[] $keywords
	 * @return string[]
	 */
	public static function normalize_keywords( array $keywords ): array {
		$out = array();
		foreach ( $keywords as $kw ) {
			if ( ! is_string( $kw ) ) {
				continue;
			}
			$lower = strtolower( $kw );
			if ( '' === $lower ) {
				continue;
			}
			$out[ $lower ] = true;
		}
		return array_keys( $out );
	}
}
