<?php
/**
 * Project a Connected Bridges table row from raw OAuth data.
 *
 * Pure logic — given a client row + the most-recent token row + the last
 * interactive consent timestamp, returns a flat array of display values.
 * Tested without any DB.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Admin\Bridges
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Admin\Bridges;

use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\PolicyStore;

/**
 * Build the display-ready shape of one bridge row.
 */
final class BridgeRowProjector {

	/** Number of days before the silent-cap to start showing the warning icon (per H.2.4). */
	public const SILENT_WARNING_DAYS_BEFORE_CAP = 30;

	/**
	 * Project a single row.
	 *
	 * @param object   $client                 Row from kl_oauth_clients (client_id, client_name, scopes, registered_at, ...)
	 * @param ?object  $latest_token           Most recent active token row, or null when none.
	 * @param ?int     $last_interactive_unix  UNIX timestamp of last interactive consent.
	 * @param int      $now_unix               Injected for testability.
	 * @param int      $silent_cap_days        From {@see PolicyStore::consent_max_silent_days()}.
	 * @return array{
	 *   client_id:string,
	 *   client_name:string,
	 *   software:string,
	 *   user_id:int,
	 *   scopes:string[],
	 *   last_used_at:?string,
	 *   expires_at:?string,
	 *   last_consent_days:?int,
	 *   show_silent_warning:bool,
	 *   registered_at:string
	 * }
	 */
	public static function project(
		object  $client,
		?object $latest_token,
		?int    $last_interactive_unix,
		int     $now_unix,
		int     $silent_cap_days
	): array {
		$client_id   = (string) ( $client->client_id ?? '' );
		$client_name = (string) ( $client->client_name ?? '' );
		$software_id = (string) ( $client->software_id ?? '' );
		$software_v  = (string) ( $client->software_version ?? '' );
		$software    = trim( $software_id . ( '' !== $software_v ? ' ' . $software_v : '' ) );

		$scope_str = (string) ( $latest_token->scope ?? $client->scopes ?? '' );
		$scopes    = '' === $scope_str ? array() : array_values( array_filter( explode( ' ', $scope_str ) ) );

		$user_id = (int) ( $latest_token->user_id ?? 0 );

		$last_used = isset( $latest_token->last_used_at ) && '' !== (string) $latest_token->last_used_at
			? (string) $latest_token->last_used_at
			: null;

		$expires = isset( $latest_token->expires_at ) && '' !== (string) $latest_token->expires_at
			? (string) $latest_token->expires_at
			: null;

		$days_since = null;
		if ( null !== $last_interactive_unix ) {
			$delta      = max( 0, $now_unix - $last_interactive_unix );
			$days_since = (int) floor( $delta / 86400 );
		}

		$show_warning = false;
		if ( null !== $days_since ) {
			$threshold    = max( 0, $silent_cap_days - self::SILENT_WARNING_DAYS_BEFORE_CAP );
			$show_warning = $days_since >= $threshold;
		}

		return array(
			'client_id'           => $client_id,
			'client_name'         => $client_name,
			'software'            => $software,
			'user_id'             => $user_id,
			'scopes'              => $scopes,
			'last_used_at'        => $last_used,
			'expires_at'          => $expires,
			'last_consent_days'   => $days_since,
			'show_silent_warning' => $show_warning,
			'registered_at'       => (string) ( $client->registered_at ?? '' ),
		);
	}
}