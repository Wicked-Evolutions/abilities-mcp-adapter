<?php
/**
 * Pure parameter validation for /oauth/authorize.
 *
 * Implements Appendix H.3.6's pre-login validation order: client_id and
 * redirect_uri are checked BEFORE we even consider the operator's login
 * state. If either is malformed, the response is 400 HTML — never a redirect
 * that leaks "user is/isn't logged in" state to an unauthenticated attacker.
 *
 * Implements Appendix H.3.5 for the `state` parameter: required, ≤256 chars,
 * round-tripped opaquely.
 *
 * Returns a typed result so the endpoint can split error rendering from
 * happy-path consent decisions.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Consent;

use WickedEvolutions\McpAdapter\Auth\OAuth\ClientRegistry;
use WickedEvolutions\McpAdapter\Auth\OAuth\ScopeRegistry;

/**
 * Validation outcome for an /oauth/authorize request.
 *
 * Two error categories:
 *   - PRE_REDIRECT_ERROR — client_id or redirect_uri invalid; response MUST be 400 HTML, never redirect (H.3.6).
 *   - REDIRECTABLE_ERROR — client_id+redirect_uri are good; OAuth-spec error returned via redirect with `error=...` (H.3.5/H.3.6).
 */
final class AuthorizeValidationResult {

	public const OK                 = 'ok';
	public const PRE_REDIRECT_ERROR = 'pre_redirect_error';
	public const REDIRECTABLE_ERROR = 'redirectable_error';

	public function __construct(
		public readonly string  $status,
		public readonly ?object $client,
		public readonly string  $redirect_uri,
		public readonly array   $requested_scopes,
		public readonly string  $code_challenge,
		public readonly string  $state,
		public readonly string  $resource,
		public readonly string  $error_code = '',
		public readonly string  $error_description = ''
	) {}

	public function is_ok(): bool {
		return self::OK === $this->status;
	}

	public function is_pre_redirect_error(): bool {
		return self::PRE_REDIRECT_ERROR === $this->status;
	}

	public function is_redirectable_error(): bool {
		return self::REDIRECTABLE_ERROR === $this->status;
	}
}

/**
 * Pure validation of the /oauth/authorize query parameters.
 */
final class AuthorizeRequestValidator {

	/** Hard ceiling on `state` from Appendix H.3.5. */
	public const MAX_STATE_LENGTH = 256;

	/**
	 * Validate per the locked Appendix H.3.6 order.
	 *
	 * @param array  $params   Raw $_GET (or POST body) — values are coerced to strings here.
	 * @param string $resource_indicator The site's expected resource indicator URL.
	 */
	public static function validate( array $params, string $resource_indicator ): AuthorizeValidationResult {
		$client_id      = self::str( $params['client_id'] ?? '' );
		$redirect_uri   = self::str( $params['redirect_uri'] ?? '' );
		$response_type  = self::str( $params['response_type'] ?? '' );
		$scope          = self::str( $params['scope'] ?? '' );
		$state          = self::str( $params['state'] ?? '' );
		$code_challenge = self::str( $params['code_challenge'] ?? '' );
		$code_method    = self::str( $params['code_challenge_method'] ?? '' );
		$resource       = self::str( $params['resource'] ?? '' );

		// === H.3.6 step 1: client_id absent or malformed → 400 HTML, no redirect ===
		if ( '' === $client_id ) {
			return self::pre_redirect_error( 'invalid_request', 'client_id is required.' );
		}

		// === H.3.6 step 2: client lookup → 400 HTML if not found / revoked ===
		$client = ClientRegistry::find( $client_id );
		if ( ! $client ) {
			return self::pre_redirect_error( 'invalid_client', 'Client not found or revoked.' );
		}

		// === H.3.6 step 3: redirect_uri validation → 400 HTML if invalid ===
		if ( '' === $redirect_uri || ! ClientRegistry::redirect_uri_valid( $client, $redirect_uri ) ) {
			return self::pre_redirect_error( 'invalid_request', 'redirect_uri is not registered for this client.' );
		}

		// From this point on, errors are redirectable per OAuth 2.1 — `error=...&state=...` to redirect_uri.

		// response_type must be `code`.
		if ( 'code' !== $response_type ) {
			return self::redirectable_error( $client, $redirect_uri, $state, 'unsupported_response_type', 'Only response_type=code is supported.' );
		}

		// === H.3.6 step 5: PKCE S256 ===
		if ( '' === $code_challenge ) {
			return self::redirectable_error( $client, $redirect_uri, $state, 'invalid_request', 'code_challenge is required.' );
		}
		if ( '' !== $code_method && 'S256' !== $code_method ) {
			return self::redirectable_error( $client, $redirect_uri, $state, 'invalid_request', 'code_challenge_method must be S256.' );
		}

		// === H.3.5 / H.3.6 step 6: state required, ≤256 chars ===
		if ( '' === $state ) {
			return self::redirectable_error( $client, $redirect_uri, '', 'invalid_request', 'state parameter is required.' );
		}
		if ( strlen( $state ) > self::MAX_STATE_LENGTH ) {
			return self::redirectable_error( $client, $redirect_uri, '', 'invalid_request', 'state parameter exceeds 256 characters.' );
		}

		// Resource indicator MUST match this site's MCP endpoint when present (H.1.2 already binds tokens; we enforce it up front so the bridge can't claim a different resource).
		if ( '' !== $resource && ! hash_equals( $resource_indicator, $resource ) ) {
			return self::redirectable_error( $client, $redirect_uri, $state, 'invalid_target', 'resource indicator does not match this server.' );
		}
		// If absent, fill with the site's own resource indicator — the issued token will be bound to it.
		if ( '' === $resource ) {
			$resource = $resource_indicator;
		}

		// === H.3.6 step 4: scope validation ===
		// Empty scope is allowed (defaults to no abilities) but we require explicit scope to avoid surprises.
		$requested_raw = '' === $scope ? array() : array_values( array_filter( explode( ' ', $scope ) ) );
		if ( empty( $requested_raw ) ) {
			return self::redirectable_error( $client, $redirect_uri, $state, 'invalid_scope', 'scope parameter is required.' );
		}
		$expanded = ScopeRegistry::expand( $requested_raw );
		$unknown  = ScopeRegistry::unknown_scopes( $expanded );
		if ( ! empty( $unknown ) ) {
			return self::redirectable_error( $client, $redirect_uri, $state, 'invalid_scope', 'Unknown scope(s): ' . implode( ' ', $unknown ) );
		}

		// All checks passed.
		return new AuthorizeValidationResult(
			AuthorizeValidationResult::OK,
			$client,
			$redirect_uri,
			$expanded,
			$code_challenge,
			$state,
			$resource
		);
	}

	/** Coerce + sanitize a single scalar param to a string. */
	private static function str( mixed $value ): string {
		if ( is_string( $value ) ) {
			return trim( $value );
		}
		if ( is_scalar( $value ) ) {
			return trim( (string) $value );
		}
		return '';
	}

	private static function pre_redirect_error( string $code, string $description ): AuthorizeValidationResult {
		return new AuthorizeValidationResult(
			AuthorizeValidationResult::PRE_REDIRECT_ERROR,
			null,
			'',
			array(),
			'',
			'',
			'',
			$code,
			$description
		);
	}

	private static function redirectable_error( object $client, string $redirect_uri, string $state, string $code, string $description ): AuthorizeValidationResult {
		return new AuthorizeValidationResult(
			AuthorizeValidationResult::REDIRECTABLE_ERROR,
			$client,
			$redirect_uri,
			array(),
			'',
			$state,
			'',
			$code,
			$description
		);
	}
}
