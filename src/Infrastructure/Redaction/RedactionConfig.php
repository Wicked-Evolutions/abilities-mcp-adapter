<?php
/**
 * Redaction configuration — default keyword lists, options, and exemptions.
 *
 * Three buckets:
 *   - Bucket 1 (secrets): always-on, never disabled. Cannot be configured.
 *   - Bucket 2 (payment / regulated IDs): default-on, configurable via Admin UI only.
 *   - Bucket 3 (contact PII / access labels): default-on, configurable via Admin UI or AI.
 *
 * Option I/O is delegated to {@see SafetySettingsRepository} (Launch Gate runbook v0.2.0
 * single source of truth). This class remains the runtime entry point for the redactor
 * itself and the public surface for the documented filter hooks
 * (`abilities_mcp_redaction_master_enabled`, `abilities_mcp_redaction_keywords`).
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Infrastructure\Redaction;

use WickedEvolutions\McpAdapter\Settings\SafetySettingsRepository;

/**
 * Redaction configuration loader.
 */
final class RedactionConfig {

	public const OPTION_MASTER_ENABLED      = SafetySettingsRepository::OPTION_MASTER_ENABLED;
	public const OPTION_BUCKET3_KEYWORDS    = SafetySettingsRepository::OPTION_BUCKET3_KEYWORDS;
	public const OPTION_BUCKET3_EXEMPTIONS  = SafetySettingsRepository::OPTION_BUCKET3_EXEMPTIONS;
	public const OPTION_BUCKET2_EXEMPTIONS  = SafetySettingsRepository::OPTION_BUCKET2_EXEMPTIONS;

	public const BUCKET_SECRETS  = SafetySettingsRepository::BUCKET_SECRETS;
	public const BUCKET_PAYMENT  = SafetySettingsRepository::BUCKET_PAYMENT;
	public const BUCKET_CONTACT  = SafetySettingsRepository::BUCKET_CONTACT;

	/**
	 * Bucket 1 — always-on secrets.
	 *
	 * @return string[]
	 */
	public static function bucket1_keywords(): array {
		return SafetySettingsRepository::bucket1_default_keywords();
	}

	/**
	 * Bucket 2 — payment + regulated IDs (active list: defaults plus customs minus removals).
	 *
	 * @return string[]
	 */
	public static function bucket2_keywords(): array {
		return SafetySettingsRepository::get_active_keywords( SafetySettingsRepository::BUCKET_PAYMENT );
	}

	/**
	 * Bucket 3 — contact PII / access labels (default list before custom additions).
	 *
	 * @return string[]
	 */
	public static function bucket3_default_keywords(): array {
		return SafetySettingsRepository::bucket3_default_keywords();
	}

	/**
	 * Whether Bucket 2 + Bucket 3 redaction is active.
	 *
	 * Bucket 1 ignores this toggle entirely.
	 *
	 * @return bool
	 */
	public static function is_master_enabled(): bool {
		$enabled = SafetySettingsRepository::is_master_enabled();

		if ( function_exists( 'apply_filters' ) ) {
			$enabled = (bool) apply_filters( self::OPTION_MASTER_ENABLED, $enabled );
		}

		return $enabled;
	}

	/**
	 * Active Bucket 3 keyword list (defaults + custom additions − removed defaults, after filter).
	 *
	 * @return string[] Lower-cased canonical names.
	 */
	public static function bucket3_keywords(): array {
		$merged = SafetySettingsRepository::get_active_keywords( SafetySettingsRepository::BUCKET_CONTACT );

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

		$exempt = SafetySettingsRepository::get_exemptions( $bucket );

		return in_array( $ability_name, $exempt, true );
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
