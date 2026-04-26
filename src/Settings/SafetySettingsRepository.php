<?php
/**
 * Safety settings repository — read/write the option keys configured by
 * the Safety Settings UI and the AI-callable settings abilities.
 *
 * Option key contract (DB-2 + DB-3 share these):
 *
 *   abilities_mcp_redaction_master_enabled  (bool, default true)
 *   abilities_mcp_redaction_keywords        (string[], custom Bucket 3 additions)
 *   abilities_mcp_bucket2_keywords          (string[], custom Bucket 2 additions — written here, read by DB-2 after rebase)
 *   abilities_mcp_bucket3_exemptions        (string[], ability names exempt from Bucket 3)
 *   abilities_mcp_bucket2_exemptions        (string[], ability names exempt from Bucket 2 — Admin-UI only)
 *   abilities_mcp_trusted_proxy_enabled     (bool, default false)
 *   abilities_mcp_trusted_proxy_mode        (string, 'cloudflare' | 'custom', default 'cloudflare')
 *   abilities_mcp_trusted_proxy_allowlist   (string, newline-separated CIDR list)
 *
 * Bucket 2 weakening (remove default keyword, exempt ability) and the master
 * toggle off are Admin-UI-only — abilities cannot reach those write paths.
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
 * Single source of truth for safety-setting option I/O.
 *
 * Hardcoded Bucket 1 + Bucket 2 default lists live here too so the UI and
 * abilities can render them without depending on DB-2's RedactionConfig
 * before that branch merges. Once DB-2 is integrated, RedactionConfig will
 * remain authoritative for the runtime filter — this class stays the
 * authoritative configuration surface (UI/abilities), and the two stay
 * aligned by referencing the same option keys.
 */
final class SafetySettingsRepository {

	public const OPTION_MASTER_ENABLED         = 'abilities_mcp_redaction_master_enabled';
	public const OPTION_BUCKET3_KEYWORDS       = 'abilities_mcp_redaction_keywords';
	public const OPTION_BUCKET2_KEYWORDS       = 'abilities_mcp_bucket2_keywords';
	public const OPTION_BUCKET3_EXEMPTIONS     = 'abilities_mcp_bucket3_exemptions';
	public const OPTION_BUCKET2_EXEMPTIONS     = 'abilities_mcp_bucket2_exemptions';
	public const OPTION_TRUSTED_PROXY_ENABLED  = 'abilities_mcp_trusted_proxy_enabled';
	public const OPTION_TRUSTED_PROXY_MODE     = 'abilities_mcp_trusted_proxy_mode';
	public const OPTION_TRUSTED_PROXY_ALLOWLIST = 'abilities_mcp_trusted_proxy_allowlist';

	public const BUCKET_SECRETS = 1;
	public const BUCKET_PAYMENT = 2;
	public const BUCKET_CONTACT = 3;

	public const PROXY_MODE_CLOUDFLARE = 'cloudflare';
	public const PROXY_MODE_CUSTOM     = 'custom';

	/**
	 * Bucket 1 — always-on secrets. Hardcoded; not configurable.
	 *
	 * Mirrors DB-2's RedactionConfig::bucket1_keywords(). Kept in sync by
	 * convention; both lists must agree at integration time.
	 *
	 * @return string[]
	 */
	public static function bucket1_default_keywords(): array {
		return array(
			'password', 'pass', 'passwd', 'user_pass', 'user_password',
			'db_password', 'database_password', 'smtp_password',
			'imap_password', 'pop_password', 'ftp_password', 'ssh_password',
			'api_key', 'api_secret', 'consumer_key', 'consumer_secret',
			'client_secret', 'client_key', 'private_key', 'license_key',
			'serial_key', 'activation_key', 'app_key', 'app_secret',
			'webhook_secret', 'webhook_key', 'signing_key', 'encryption_key',
			'master_key', 'secret_key',
			'access_token', 'refresh_token', 'bearer_token', 'auth_token',
			'authentication_token', 'oauth_token', 'oauth_secret',
			'session_token', 'session_tokens', 'session_secret', 'csrf_token',
			'nonce_token', 'id_token', 'personal_access_token',
			'auth_key', 'secure_auth_key', 'logged_in_key', 'nonce_key',
			'auth_salt', 'secure_auth_salt', 'logged_in_salt', 'nonce_salt',
		);
	}

	/**
	 * Bucket 2 — payment + regulated identifiers (default list).
	 *
	 * @return string[]
	 */
	public static function bucket2_default_keywords(): array {
		return array(
			'card_number', 'cardnumber', 'cc_number', 'pan',
			'cvv', 'cvc', 'cv2', 'card_cvv', 'card_cvc', 'card_pin',
			'ssn', 'social_security_number', 'social_security',
			'tax_id', 'ein', 'tin', 'vat_number', 'vat_id',
		);
	}

	/**
	 * Bucket 3 — contact PII / access labels (default list).
	 *
	 * @return string[]
	 */
	public static function bucket3_default_keywords(): array {
		return array(
			'email', 'user_email', 'customer_email', 'contact_email',
			'billing_email', 'shipping_email', 'payment_email',
			'phone', 'phone_number', 'mobile', 'mobile_number',
			'tel', 'telephone', 'billing_phone', 'shipping_phone', 'contact_phone',
			'address', 'street_address', 'address_line_1', 'address_line_2',
			'street', 'street1', 'street2',
			'billing_address', 'shipping_address',
			'billing_address_1', 'shipping_address_1',
			'user_login', 'username',
			'ip', 'ip_address', 'user_ip', 'client_ip', 'remote_ip', 'last_ip',
			'birthdate', 'birth_date', 'date_of_birth', 'dob',
			'public_key',
		);
	}

	/**
	 * Removed-defaults storage option for Bucket 3.
	 *
	 * Default Bucket 3 keywords cannot be deleted; they can be marked as
	 * removed so RedactionConfig::bucket3_keywords() can subtract them via
	 * the `abilities_mcp_redaction_keywords` filter. Removal is reversible
	 * by the operator (Restore defaults).
	 */
	public const OPTION_BUCKET3_REMOVED_DEFAULTS = 'abilities_mcp_redaction_keywords_removed_defaults';

	/**
	 * Removed-defaults storage option for Bucket 2.
	 *
	 * @see self::OPTION_BUCKET3_REMOVED_DEFAULTS
	 */
	public const OPTION_BUCKET2_REMOVED_DEFAULTS = 'abilities_mcp_bucket2_keywords_removed_defaults';

	/**
	 * Whether the master redaction toggle is on.
	 */
	public static function is_master_enabled(): bool {
		return (bool) get_option( self::OPTION_MASTER_ENABLED, true );
	}

	/**
	 * Set master toggle.
	 *
	 * Admin-UI-only callers should use this directly. Abilities never call
	 * this with `$enabled = false` — that path requires the in-UI checkbox.
	 *
	 * @param bool $enabled
	 */
	public static function set_master_enabled( bool $enabled ): void {
		update_option( self::OPTION_MASTER_ENABLED, $enabled );
	}

	/**
	 * Custom keywords added by the operator for the given bucket.
	 *
	 * Bucket 1 always returns []: it is hardcoded and not extendable from
	 * the operator surface.
	 *
	 * @param int $bucket
	 * @return string[]
	 */
	public static function get_custom_keywords( int $bucket ): array {
		if ( self::BUCKET_SECRETS === $bucket ) {
			return array();
		}
		$option = self::BUCKET_PAYMENT === $bucket
			? self::OPTION_BUCKET2_KEYWORDS
			: self::OPTION_BUCKET3_KEYWORDS;

		$value = get_option( $option, array() );
		return self::clean_keyword_list( is_array( $value ) ? $value : array() );
	}

	/**
	 * Removed-defaults set for a bucket (operator-removed default keywords).
	 *
	 * @param int $bucket
	 * @return string[]
	 */
	public static function get_removed_defaults( int $bucket ): array {
		if ( self::BUCKET_SECRETS === $bucket ) {
			return array();
		}
		$option = self::BUCKET_PAYMENT === $bucket
			? self::OPTION_BUCKET2_REMOVED_DEFAULTS
			: self::OPTION_BUCKET3_REMOVED_DEFAULTS;

		$value = get_option( $option, array() );
		return self::clean_keyword_list( is_array( $value ) ? $value : array() );
	}

	/**
	 * Active keyword list for the given bucket: defaults minus removed-defaults
	 * plus custom additions, deduped and lower-cased.
	 *
	 * @param int $bucket
	 * @return string[]
	 */
	public static function get_active_keywords( int $bucket ): array {
		switch ( $bucket ) {
			case self::BUCKET_SECRETS:
				$defaults = self::bucket1_default_keywords();
				$customs  = array();
				$removed  = array();
				break;
			case self::BUCKET_PAYMENT:
				$defaults = self::bucket2_default_keywords();
				$customs  = self::get_custom_keywords( self::BUCKET_PAYMENT );
				$removed  = self::get_removed_defaults( self::BUCKET_PAYMENT );
				break;
			case self::BUCKET_CONTACT:
				$defaults = self::bucket3_default_keywords();
				$customs  = self::get_custom_keywords( self::BUCKET_CONTACT );
				$removed  = self::get_removed_defaults( self::BUCKET_CONTACT );
				break;
			default:
				return array();
		}

		$removed_set = array_flip( array_map( 'strtolower', $removed ) );
		$active      = array();
		foreach ( $defaults as $kw ) {
			if ( ! isset( $removed_set[ strtolower( $kw ) ] ) ) {
				$active[] = $kw;
			}
		}
		foreach ( $customs as $kw ) {
			$active[] = $kw;
		}
		return self::clean_keyword_list( $active );
	}

	/**
	 * Add a custom keyword to a bucket. Returns true if newly added.
	 *
	 * Strengthening operation — no friction. Bucket 1 is rejected.
	 *
	 * @param int    $bucket
	 * @param string $keyword
	 * @return bool|\WP_Error
	 */
	public static function add_custom_keyword( int $bucket, string $keyword ) {
		$keyword = self::sanitize_keyword( $keyword );
		if ( '' === $keyword ) {
			return new \WP_Error( 'empty_keyword', 'Keyword must be a non-empty string.' );
		}
		if ( self::BUCKET_SECRETS === $bucket ) {
			return new \WP_Error( 'bucket1_locked', 'Bucket 1 is hardcoded and cannot accept custom keywords.' );
		}
		if ( self::BUCKET_PAYMENT !== $bucket && self::BUCKET_CONTACT !== $bucket ) {
			return new \WP_Error( 'invalid_bucket', 'Bucket must be 2 or 3.' );
		}

		// If this keyword is currently a removed default, restoring it is the right move.
		$removed = self::get_removed_defaults( $bucket );
		$removed_index = array_search( $keyword, array_map( 'strtolower', $removed ), true );
		if ( false !== $removed_index ) {
			unset( $removed[ $removed_index ] );
			self::write_keyword_option( self::removed_defaults_option( $bucket ), array_values( $removed ) );
			return true;
		}

		// Already present (default or custom)? No-op success.
		$active = array_flip( self::get_active_keywords( $bucket ) );
		if ( isset( $active[ $keyword ] ) ) {
			return false;
		}

		$customs   = self::get_custom_keywords( $bucket );
		$customs[] = $keyword;
		self::write_keyword_option( self::custom_keywords_option( $bucket ), $customs );
		return true;
	}

	/**
	 * Remove a keyword the operator previously added (custom). Returns true
	 * if a custom entry was removed; false if no matching custom entry.
	 *
	 * Reversal of the operator's own work — no friction. Does not touch
	 * default-keyword removals (those go through remove_default_*).
	 *
	 * @param int    $bucket
	 * @param string $keyword
	 * @return bool|\WP_Error
	 */
	public static function remove_custom_keyword( int $bucket, string $keyword ) {
		$keyword = self::sanitize_keyword( $keyword );
		if ( '' === $keyword ) {
			return new \WP_Error( 'empty_keyword', 'Keyword must be a non-empty string.' );
		}
		if ( self::BUCKET_PAYMENT !== $bucket && self::BUCKET_CONTACT !== $bucket ) {
			return new \WP_Error( 'invalid_bucket', 'Bucket must be 2 or 3.' );
		}

		$customs = self::get_custom_keywords( $bucket );
		$lower   = array_map( 'strtolower', $customs );
		$index   = array_search( $keyword, $lower, true );
		if ( false === $index ) {
			return false;
		}
		unset( $customs[ $index ] );
		self::write_keyword_option( self::custom_keywords_option( $bucket ), array_values( $customs ) );
		return true;
	}

	/**
	 * Mark a default keyword as removed for the given bucket. Returns true
	 * if newly removed.
	 *
	 * Bucket 3 path: friction = in-chat 1/2 confirmation token (enforced by ability).
	 * Bucket 2 path: Admin-UI only — abilities must NOT call this with $bucket=2.
	 *
	 * Returns WP_Error on invalid bucket / non-default keyword / empty.
	 *
	 * @param int    $bucket
	 * @param string $keyword
	 * @return bool|\WP_Error
	 */
	public static function remove_default_keyword( int $bucket, string $keyword ) {
		$keyword = self::sanitize_keyword( $keyword );
		if ( '' === $keyword ) {
			return new \WP_Error( 'empty_keyword', 'Keyword must be a non-empty string.' );
		}

		if ( self::BUCKET_PAYMENT === $bucket ) {
			$defaults = self::bucket2_default_keywords();
		} elseif ( self::BUCKET_CONTACT === $bucket ) {
			$defaults = self::bucket3_default_keywords();
		} else {
			return new \WP_Error( 'invalid_bucket', 'Bucket must be 2 or 3.' );
		}

		if ( ! in_array( $keyword, array_map( 'strtolower', $defaults ), true ) ) {
			return new \WP_Error( 'not_a_default', sprintf( 'Keyword "%s" is not a default in bucket %d. Use remove_custom_keyword instead.', $keyword, $bucket ) );
		}

		$removed = self::get_removed_defaults( $bucket );
		if ( in_array( $keyword, array_map( 'strtolower', $removed ), true ) ) {
			return false;
		}
		$removed[] = $keyword;
		self::write_keyword_option( self::removed_defaults_option( $bucket ), $removed );
		return true;
	}

	/**
	 * Restore Bucket 2 + Bucket 3 lists to factory defaults.
	 *
	 * Clears custom additions and removed-defaults for both buckets.
	 */
	public static function restore_defaults(): void {
		delete_option( self::OPTION_BUCKET3_KEYWORDS );
		delete_option( self::OPTION_BUCKET2_KEYWORDS );
		delete_option( self::OPTION_BUCKET3_REMOVED_DEFAULTS );
		delete_option( self::OPTION_BUCKET2_REMOVED_DEFAULTS );
	}

	/**
	 * Per-ability exemption list for the given bucket.
	 *
	 * @param int $bucket
	 * @return string[]
	 */
	public static function get_exemptions( int $bucket ): array {
		$option = self::exemptions_option( $bucket );
		if ( null === $option ) {
			return array();
		}
		$value = get_option( $option, array() );
		return self::clean_ability_list( is_array( $value ) ? $value : array() );
	}

	/**
	 * Add an ability to a bucket's exemption list. Returns true if newly added.
	 *
	 * Bucket 3 path: friction = in-chat 1/2 confirmation token (enforced by ability).
	 * Bucket 2 path: Admin-UI only — abilities must NOT call this with $bucket=2.
	 *
	 * @param int    $bucket
	 * @param string $ability_name
	 * @return bool|\WP_Error
	 */
	public static function add_exemption( int $bucket, string $ability_name ) {
		$ability_name = self::sanitize_ability_name( $ability_name );
		if ( '' === $ability_name ) {
			return new \WP_Error( 'empty_ability', 'Ability name must be a non-empty string.' );
		}
		$option = self::exemptions_option( $bucket );
		if ( null === $option ) {
			return new \WP_Error( 'invalid_bucket', 'Bucket must be 2 or 3.' );
		}
		$current = self::get_exemptions( $bucket );
		if ( in_array( $ability_name, $current, true ) ) {
			return false;
		}
		$current[] = $ability_name;
		update_option( $option, array_values( array_unique( $current ) ) );
		return true;
	}

	/**
	 * Remove an ability from a bucket's exemption list. Returns true if it was present.
	 *
	 * Strengthening operation — no friction.
	 *
	 * @param int    $bucket
	 * @param string $ability_name
	 * @return bool|\WP_Error
	 */
	public static function remove_exemption( int $bucket, string $ability_name ) {
		$ability_name = self::sanitize_ability_name( $ability_name );
		if ( '' === $ability_name ) {
			return new \WP_Error( 'empty_ability', 'Ability name must be a non-empty string.' );
		}
		$option = self::exemptions_option( $bucket );
		if ( null === $option ) {
			return new \WP_Error( 'invalid_bucket', 'Bucket must be 2 or 3.' );
		}
		$current = self::get_exemptions( $bucket );
		$filtered = array_values( array_filter( $current, static fn( $name ) => $name !== $ability_name ) );
		if ( count( $filtered ) === count( $current ) ) {
			return false;
		}
		update_option( $option, $filtered );
		return true;
	}

	// Trusted proxy ------------------------------------------------------

	public static function is_trusted_proxy_enabled(): bool {
		return (bool) get_option( self::OPTION_TRUSTED_PROXY_ENABLED, false );
	}

	public static function set_trusted_proxy_enabled( bool $enabled ): void {
		update_option( self::OPTION_TRUSTED_PROXY_ENABLED, $enabled );
	}

	public static function get_trusted_proxy_mode(): string {
		$value = (string) get_option( self::OPTION_TRUSTED_PROXY_MODE, self::PROXY_MODE_CLOUDFLARE );
		return self::PROXY_MODE_CUSTOM === $value ? self::PROXY_MODE_CUSTOM : self::PROXY_MODE_CLOUDFLARE;
	}

	public static function set_trusted_proxy_mode( string $mode ): void {
		$mode = self::PROXY_MODE_CUSTOM === $mode ? self::PROXY_MODE_CUSTOM : self::PROXY_MODE_CLOUDFLARE;
		update_option( self::OPTION_TRUSTED_PROXY_MODE, $mode );
	}

	/**
	 * Stored allowlist as plain newline-delimited text (for round-trip in textarea).
	 */
	public static function get_trusted_proxy_allowlist_raw(): string {
		return (string) get_option( self::OPTION_TRUSTED_PROXY_ALLOWLIST, '' );
	}

	public static function set_trusted_proxy_allowlist_raw( string $raw ): void {
		update_option( self::OPTION_TRUSTED_PROXY_ALLOWLIST, $raw );
	}

	// Internals ----------------------------------------------------------

	private static function clean_keyword_list( array $list ): array {
		$out = array();
		foreach ( $list as $kw ) {
			if ( ! is_string( $kw ) ) {
				continue;
			}
			$lower = strtolower( trim( $kw ) );
			if ( '' === $lower ) {
				continue;
			}
			$out[ $lower ] = true;
		}
		return array_keys( $out );
	}

	private static function clean_ability_list( array $list ): array {
		$out = array();
		foreach ( $list as $name ) {
			if ( ! is_string( $name ) ) {
				continue;
			}
			$clean = self::sanitize_ability_name( $name );
			if ( '' !== $clean ) {
				$out[ $clean ] = true;
			}
		}
		return array_keys( $out );
	}

	private static function sanitize_keyword( string $keyword ): string {
		// Field-name allowlist: lower alphanumeric + underscore + hyphen + dot, capped 64.
		$keyword = strtolower( trim( $keyword ) );
		$keyword = preg_replace( '/[^a-z0-9_\-\.]/', '', $keyword ) ?? '';
		if ( strlen( $keyword ) > 64 ) {
			$keyword = substr( $keyword, 0, 64 );
		}
		return $keyword;
	}

	private static function sanitize_ability_name( string $name ): string {
		// Ability names are namespaced like `users/list` or `mcp-adapter/get-started`.
		$name = trim( $name );
		$name = preg_replace( '/[^a-zA-Z0-9_\-\/]/', '', $name ) ?? '';
		if ( strlen( $name ) > 191 ) {
			$name = substr( $name, 0, 191 );
		}
		return $name;
	}

	private static function custom_keywords_option( int $bucket ): string {
		return self::BUCKET_PAYMENT === $bucket
			? self::OPTION_BUCKET2_KEYWORDS
			: self::OPTION_BUCKET3_KEYWORDS;
	}

	private static function removed_defaults_option( int $bucket ): string {
		return self::BUCKET_PAYMENT === $bucket
			? self::OPTION_BUCKET2_REMOVED_DEFAULTS
			: self::OPTION_BUCKET3_REMOVED_DEFAULTS;
	}

	/**
	 * Returns null when bucket invalid; never returns Bucket-1 option.
	 */
	private static function exemptions_option( int $bucket ): ?string {
		if ( self::BUCKET_PAYMENT === $bucket ) {
			return self::OPTION_BUCKET2_EXEMPTIONS;
		}
		if ( self::BUCKET_CONTACT === $bucket ) {
			return self::OPTION_BUCKET3_EXEMPTIONS;
		}
		return null;
	}

	private static function write_keyword_option( string $option, array $list ): void {
		update_option( $option, array_values( array_unique( self::clean_keyword_list( $list ) ) ) );
	}
}
