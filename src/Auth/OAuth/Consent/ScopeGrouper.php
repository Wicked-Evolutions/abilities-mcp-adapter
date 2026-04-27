<?php
/**
 * Group scope strings by module for the consent screen.
 *
 * The full scope catalog is owned by {@see ScopeRegistry}; this class
 * arranges already-known scope strings into the visual buckets the consent
 * screen renders. Pure logic — no HTML.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Consent;

use WickedEvolutions\McpAdapter\Auth\OAuth\ScopeRegistry;

/**
 * Group already-known scope strings by their module segment.
 */
final class ScopeGrouper {

	/**
	 * Group scopes by their middle module segment.
	 *
	 * Scope shape is `abilities:<module>:<op>` for module-scoped grants and
	 * `abilities:<umbrella>` for the three umbrella grants. Umbrella scopes
	 * group under the synthetic key 'umbrella'.
	 *
	 * Output ordering: umbrella first, then modules alphabetically. Within a
	 * module, scopes preserve the order given (already sorted by callers).
	 *
	 * @param string[] $scopes Already-validated scope strings.
	 * @return array<string, string[]> Module slug → scope strings.
	 */
	public static function group( array $scopes ): array {
		$out = array();
		foreach ( $scopes as $scope ) {
			if ( ! is_string( $scope ) ) {
				continue;
			}
			$parts = explode( ':', $scope );
			// 'abilities:read' → umbrella; 'abilities:content:read' → module 'content'.
			$module = ( count( $parts ) === 2 ) ? 'umbrella' : ( $parts[1] ?? 'umbrella' );
			$out[ $module ][] = $scope;
		}

		// Stable order: umbrella first, then alphabetical modules.
		uksort(
			$out,
			static function ( string $a, string $b ): int {
				if ( 'umbrella' === $a ) {
					return -1;
				}
				if ( 'umbrella' === $b ) {
					return 1;
				}
				return strcmp( $a, $b );
			}
		);

		return $out;
	}

	/**
	 * Whether a module group contains any sensitive scope.
	 *
	 * Used to render the lock icon next to module headings.
	 *
	 * @param string[] $module_scopes
	 */
	public static function group_is_sensitive( array $module_scopes ): bool {
		foreach ( $module_scopes as $scope ) {
			if ( ScopeRegistry::is_sensitive( (string) $scope ) ) {
				return true;
			}
		}
		return false;
	}
}
