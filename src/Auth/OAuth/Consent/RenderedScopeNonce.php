<?php
/**
 * Server-bound nonce that ties the consent POST to the consent GET render
 * (Appendix H.4.5 — browser-extension threat).
 *
 * The consent screen is rendered with a hidden input containing this nonce.
 * The POST handler MUST verify (a) the nonce was issued by the server, (b)
 * it has not been used already, (c) the submitted scope set is a subset of
 * the rendered scope set the nonce was issued for.
 *
 * Stored as a transient — short-lived (15 minutes) and single-use. The
 * server-side store is the only source of truth; a malicious browser
 * extension can change the visible checkboxes but cannot fabricate an
 * issued-by-server scope set behind them.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Consent;

/**
 * Issue, redeem, and verify nonces binding the consent GET to the consent POST.
 */
final class RenderedScopeNonce {

	/** Lifetime of an unused nonce (seconds). 15 minutes matches the operator's expected attention window. */
	public const TTL_SECONDS = 900;

	/** Transient key prefix. */
	private const PREFIX = 'mcp_oauth_consent_nonce_';

	/**
	 * Issue a nonce binding the rendered scope set to the user, client, redirect_uri, and the OAuth `state`.
	 *
	 * @param string[] $rendered_scopes The exact scope set rendered to the operator.
	 * @param int      $user_id         The currently logged-in user.
	 * @param string   $client_id       The OAuth client_id.
	 * @param string   $redirect_uri    The validated redirect_uri.
	 * @param string   $state           The OAuth state parameter.
	 * @return string The opaque nonce to embed in the consent form.
	 */
	public static function issue(
		array  $rendered_scopes,
		int    $user_id,
		string $client_id,
		string $redirect_uri,
		string $state
	): string {
		$nonce = bin2hex( random_bytes( 16 ) );
		$payload = array(
			'rendered_scopes' => array_values( array_unique( array_filter( $rendered_scopes, 'is_string' ) ) ),
			'user_id'         => $user_id,
			'client_id'       => $client_id,
			'redirect_uri'    => $redirect_uri,
			'state_hash'      => hash( 'sha256', $state ),
		);
		set_transient( self::PREFIX . $nonce, $payload, self::TTL_SECONDS );
		return $nonce;
	}

	/**
	 * Look up + atomically delete the nonce.
	 *
	 * Returns null if not found, expired, or already redeemed.
	 *
	 * @return array{rendered_scopes:string[],user_id:int,client_id:string,redirect_uri:string,state_hash:string}|null
	 */
	public static function redeem( string $nonce ): ?array {
		if ( '' === $nonce ) {
			return null;
		}
		$key     = self::PREFIX . $nonce;
		$payload = get_transient( $key );
		if ( ! is_array( $payload ) ) {
			return null;
		}
		// Single-use semantics — delete before returning.
		delete_transient( $key );
		return $payload;
	}

	/**
	 * Verify that a redemption matches the request and submitted scopes are a subset of rendered.
	 *
	 * @param array  $payload          Output of {@see redeem()}.
	 * @param int    $user_id          Current request user_id.
	 * @param string $client_id        Current request client_id.
	 * @param string $redirect_uri     Current request redirect_uri.
	 * @param string $state            Current request state.
	 * @param string[] $submitted_scopes Scopes the operator checked on the form.
	 */
	public static function submitted_subset_is_valid(
		array $payload,
		int $user_id,
		string $client_id,
		string $redirect_uri,
		string $state,
		array $submitted_scopes
	): bool {
		if ( (int) ( $payload['user_id'] ?? 0 ) !== $user_id ) {
			return false;
		}
		if ( ! hash_equals( (string) ( $payload['client_id'] ?? '' ), $client_id ) ) {
			return false;
		}
		if ( ! hash_equals( (string) ( $payload['redirect_uri'] ?? '' ), $redirect_uri ) ) {
			return false;
		}
		if ( ! hash_equals( (string) ( $payload['state_hash'] ?? '' ), hash( 'sha256', $state ) ) ) {
			return false;
		}
		$rendered = is_array( $payload['rendered_scopes'] ?? null ) ? $payload['rendered_scopes'] : array();
		foreach ( $submitted_scopes as $scope ) {
			if ( ! in_array( $scope, $rendered, true ) ) {
				return false;
			}
		}
		return true;
	}
}
