<?php
/**
 * OAuth scope catalog — single source of truth for all scope strings.
 *
 * Naming: abilities:<category>:<op>  (three-segment, abilities: root namespace).
 * Source: Appendix A of DESIGN — OAuth 2.1 in the Adapter 2026-04-27.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

/**
 * Registry of all valid OAuth scope strings and enforcement rules.
 */
final class ScopeRegistry {

	/**
	 * Scopes that MUST be explicitly granted — never implied by umbrella grants.
	 * These map to Bucket 1/2/3 redaction territory + admin-only WP caps.
	 */
	public const SENSITIVE_SCOPES = [
		'abilities:settings:read',
		'abilities:settings:write',
		'abilities:settings:delete',
		'abilities:users:read',
		'abilities:users:write',
		'abilities:users:delete',
		'abilities:filesystem:read',
		'abilities:filesystem:write',
		'abilities:filesystem:delete',
		'abilities:plugins:read',
		'abilities:plugins:write',
		'abilities:plugins:delete',
		'abilities:cron:read',
		'abilities:cron:write',
		'abilities:cron:delete',
		'abilities:multisite:read',
		'abilities:multisite:write',
		'abilities:multisite:delete',
		'abilities:themes:read',
		'abilities:themes:write',
		'abilities:themes:delete',
		'abilities:rewrite:read',
		'abilities:rewrite:write',
		'abilities:rewrite:delete',
	];

	/**
	 * Umbrella scopes and what they imply (excludes sensitive scopes by design).
	 * Key = umbrella scope, value = array of implied non-sensitive scopes.
	 */
	public const UMBRELLA_IMPLICATIONS = [
		'abilities:read'   => [
			'abilities:content:read',
			'abilities:taxonomies:read',
			'abilities:media:read',
			'abilities:menus:read',
			'abilities:blocks:read',
			'abilities:patterns:read',
			'abilities:meta:read',
			'abilities:comments:read',
			'abilities:revisions:read',
			'abilities:cache:read',
			'abilities:knowledge:read',
			'abilities:rest:read',
			'abilities:site-health:read',
			'abilities:diagnostic:read',
			'abilities:editorial:read',
			'abilities:site:read',
			'abilities:mcp-adapter:read',
		],
		'abilities:write'  => [
			'abilities:content:write',
			'abilities:taxonomies:write',
			'abilities:media:write',
			'abilities:menus:write',
			'abilities:blocks:write',
			'abilities:patterns:write',
			'abilities:meta:write',
			'abilities:comments:write',
			'abilities:cache:write',
			'abilities:knowledge:write',
			'abilities:mcp-adapter:write',
			// Sensitive scopes intentionally excluded.
		],
		'abilities:delete' => [
			'abilities:content:delete',
			'abilities:taxonomies:delete',
			'abilities:media:delete',
			'abilities:menus:delete',
			'abilities:patterns:delete',
			'abilities:meta:delete',
			'abilities:comments:delete',
			'abilities:revisions:delete',
			'abilities:knowledge:delete',
			// Sensitive delete scopes intentionally excluded.
		],
	];

	/** All valid scope strings (dynamic — built from catalog). */
	private static ?array $all_scopes = null;

	/**
	 * Validate that every scope in $requested is a known, valid scope string.
	 *
	 * @param array $requested
	 * @return array Invalid scope strings (empty = all valid).
	 */
	public static function unknown_scopes( array $requested ): array {
		$known = self::all_scopes();
		return array_values( array_filter( $requested, fn( $s ) => ! in_array( $s, $known, true ) ) );
	}

	/**
	 * Expand umbrella scopes to their constituent non-sensitive scopes.
	 * Does NOT expand sensitive scopes — those must be explicitly granted.
	 *
	 * @param array $scopes Raw scope list (may contain umbrella scopes).
	 * @return array Deduplicated, expanded scope list.
	 */
	public static function expand( array $scopes ): array {
		$expanded = [];
		foreach ( $scopes as $scope ) {
			$expanded[] = $scope;
			if ( isset( self::UMBRELLA_IMPLICATIONS[ $scope ] ) ) {
				$expanded = array_merge( $expanded, self::UMBRELLA_IMPLICATIONS[ $scope ] );
			}
		}
		return array_values( array_unique( $expanded ) );
	}

	/**
	 * Whether a scope is sensitive (requires explicit grant, never implied).
	 */
	public static function is_sensitive( string $scope ): bool {
		return in_array( $scope, self::SENSITIVE_SCOPES, true );
	}

	/**
	 * All valid scope strings.
	 */
	public static function all_scopes(): array {
		if ( self::$all_scopes !== null ) {
			return self::$all_scopes;
		}

		$non_sensitive_modules = [
			'content', 'taxonomies', 'media', 'menus', 'blocks', 'patterns',
			'meta', 'comments', 'revisions', 'cache', 'knowledge',
		];
		// Read-only modules — only `:read` exists; no write/delete operations
		// are registered for these categories. `site` (#101) sits here next
		// to `rest`, `site-health`, `diagnostic`, `editorial`: today's
		// `core/get-site-info` and `core/get-environment-info` are pure
		// reads; if write/delete site abilities ever land, promote `site`
		// out of this list and add the missing scopes — the
		// `ScopeCoverageDriftTest` will fail until they're declared.
		$read_only_modules     = [ 'rest', 'site-health', 'diagnostic', 'editorial', 'site' ];
		$sensitive_modules     = [
			'settings', 'users', 'filesystem', 'plugins', 'cron', 'multisite', 'themes', 'rewrite',
		];
		// Suite modules — third-party product surfaces that require explicit
		// per-suite OAuth grant. NOT covered by `abilities:read` /
		// `abilities:write` umbrellas (matches the existing pattern for
		// spectra/presto-player/astra). `surecart-ecommerce` (#102) sits
		// alongside the existing `surecart` suite scope; the registry
		// currently surfaces both because abilities-for-fluent-plugins
		// registers ecommerce abilities under the `surecart-ecommerce`
		// category while other surecart abilities use `surecart`.
		// Reconciling the two into a single canonical category is
		// post-alpha contract-polish work.
		$suite_modules         = [ 'spectra', 'presto-player', 'surecart', 'surecart-ecommerce', 'astra' ];
		// Fluent suite — per-module scopes for principled operator granularity (#74).
		// Each slug matches an abilities-for-fluent-plugins category; the OAuth
		// scope enforcer derives `abilities:<category>:<op>` from
		// WP_Ability::get_category(), so adding the scopes here is sufficient —
		// no abilities-side wiring change is needed.
		$fluent_modules        = [
			'fluent-crm',
			'fluent-community',
			'fluent-forms',
			'fluent-support',
			'fluent-boards',
			'fluent-booking',
			'fluent-smtp',
			'fluent-auth',
			'fluent-snippets',
			'fluent-messaging',
			'fluent-cart',
			'fluent-affiliate',
			'fluent-player',
		];

		$scopes = [ 'abilities:read', 'abilities:write', 'abilities:delete' ];

		foreach ( $non_sensitive_modules as $m ) {
			$scopes[] = "abilities:{$m}:read";
			$scopes[] = "abilities:{$m}:write";
			$scopes[] = "abilities:{$m}:delete";
		}
		foreach ( $read_only_modules as $m ) {
			$scopes[] = "abilities:{$m}:read";
		}
		foreach ( $sensitive_modules as $m ) {
			$scopes[] = "abilities:{$m}:read";
			$scopes[] = "abilities:{$m}:write";
			$scopes[] = "abilities:{$m}:delete";
		}
		foreach ( $suite_modules as $m ) {
			$scopes[] = "abilities:{$m}:read";
			$scopes[] = "abilities:{$m}:write";
			$scopes[] = "abilities:{$m}:delete";
		}
		foreach ( $fluent_modules as $m ) {
			$scopes[] = "abilities:{$m}:read";
			$scopes[] = "abilities:{$m}:write";
			$scopes[] = "abilities:{$m}:delete";
		}
		// Cross-module Fluent — unified user view, suite dashboard, engagement
		// scoring, multi-product onboarding. Distinct from the per-module
		// scopes above; not an umbrella over them.
		$scopes[] = 'abilities:fluent:read';
		$scopes[] = 'abilities:fluent:write';
		$scopes[] = 'abilities:fluent:delete';
		$scopes[] = 'abilities:mcp-adapter:read';
		$scopes[] = 'abilities:mcp-adapter:write';

		self::$all_scopes = array_values( array_unique( $scopes ) );
		return self::$all_scopes;
	}

	/**
	 * Categories the OAuth scope enforcer would derive `abilities:<category>:<op>`
	 * from for the given ability list.
	 *
	 * Drives the coverage-test side of Principle 9 ("Scope Coverage Is
	 * Derived Or Coverage-Tested") — the {@see \WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\ScopeCoverageDriftTest}
	 * compares the categories surfaced by the live registry (via this helper
	 * over `wp_get_abilities()` or a captured snapshot) against
	 * {@see self::all_scopes()} and fails on any unmapped category. The CI
	 * test is the actual safeguard against another `site` (#101) /
	 * `surecart-ecommerce` (#102) — manual scope-list maintenance alone is
	 * the drift this principle prevents.
	 *
	 * Categories that resolve to the empty string fall back to `mcp-adapter`
	 * at scope-derivation time (see {@see OAuthScopeEnforcer::category_segment()}).
	 * The helper preserves the empty bucket as `''` here so the drift test
	 * can flag empty-category abilities explicitly rather than silently
	 * masking them as `mcp-adapter`.
	 *
	 * @param iterable<int|string,object>|null $abilities Optional ability iterable
	 *        (each must respond to `get_category()` / `get_meta()` / `get_name()`).
	 *        Defaults to `wp_get_abilities()` when available; an empty array when
	 *        the WP Abilities API isn't loaded (unit-test stubs handle this).
	 * @return string[] Sorted, deduplicated list of category slugs.
	 */
	public static function categories_from_registry( ?iterable $abilities = null ): array {
		if ( null === $abilities ) {
			if ( ! function_exists( 'wp_get_abilities' ) ) {
				return array();
			}
			$abilities = wp_get_abilities();
			if ( ! is_array( $abilities ) && ! ( $abilities instanceof \Traversable ) ) {
				return array();
			}
		}

		$categories = array();
		foreach ( $abilities as $ability ) {
			if ( ! is_object( $ability ) || ! method_exists( $ability, 'get_category' ) ) {
				continue;
			}
			$slug              = strtolower( trim( (string) $ability->get_category() ) );
			$categories[ $slug ] = true;
		}

		$out = array_keys( $categories );
		sort( $out );
		return $out;
	}

	/**
	 * Whether the given category has at least one scope of any operation
	 * (`:read` / `:write` / `:delete`) registered.
	 *
	 * Used by the drift test to surface unmapped categories.
	 */
	public static function has_category_coverage( string $category ): bool {
		$category = strtolower( trim( $category ) );
		if ( '' === $category ) {
			// Empty category falls back to `mcp-adapter` at enforce time;
			// `mcp-adapter` is always present in the registry.
			return true;
		}
		$prefix = 'abilities:' . $category . ':';
		foreach ( self::all_scopes() as $scope ) {
			if ( 0 === strncmp( $scope, $prefix, strlen( $prefix ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Test-only seam — clears the cached `all_scopes()` list so a test that
	 * needs to assert build-from-scratch behaviour can do so. Production
	 * code never calls this; the cache exists because `all_scopes()` is hot
	 * on every OAuth request.
	 *
	 * @internal
	 */
	public static function reset_cache_for_testing(): void {
		self::$all_scopes = null;
	}
}
