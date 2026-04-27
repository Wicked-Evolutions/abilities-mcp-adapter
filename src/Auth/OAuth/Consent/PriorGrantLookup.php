<?php
/**
 * Find the most recent active token's scope set for a (client_id, user_id)
 * pair. Used to compute "previously granted" for the consent decision.
 *
 * Direct DB query — intentionally bypasses object cache, since stale data
 * here would cause incorrect auto-approve routing.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Consent;

/**
 * Read previously-granted scopes from kl_oauth_tokens.
 */
final class PriorGrantLookup {

	/**
	 * Return the scope set of the most recent non-revoked, non-expired
	 * access token for this (client_id, user_id), or empty array if none.
	 *
	 * Even an expired token counts as "previously granted scopes" for the
	 * scope-diff classification — what matters is whether the operator has
	 * ever consented to those scopes for this client. Expiry alone does not
	 * un-grant. (Revocation does.)
	 *
	 * @return string[]
	 */
	public static function scopes_for( string $client_id, int $user_id ): array {
		global $wpdb;

		$table = $wpdb->prefix . 'kl_oauth_tokens';
		$row   = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT scope FROM `{$table}`
				 WHERE client_id = %s AND user_id = %d AND revoked = 0
				 ORDER BY created_at DESC
				 LIMIT 1",
				$client_id,
				$user_id
			)
		);

		if ( ! $row || ! isset( $row->scope ) || '' === (string) $row->scope ) {
			return array();
		}
		return array_values( array_filter( explode( ' ', (string) $row->scope ) ) );
	}
}
