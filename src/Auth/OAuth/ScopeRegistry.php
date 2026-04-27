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
		$read_only_modules     = [ 'rest', 'site-health', 'diagnostic', 'editorial' ];
		$sensitive_modules     = [
			'settings', 'users', 'filesystem', 'plugins', 'cron', 'multisite', 'themes', 'rewrite',
		];
		$suite_modules         = [ 'spectra', 'presto-player', 'surecart', 'astra' ];

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
		$scopes[] = 'abilities:mcp-adapter:read';
		$scopes[] = 'abilities:mcp-adapter:write';

		self::$all_scopes = array_values( array_unique( $scopes ) );
		return self::$all_scopes;
	}
}
