<?php
/**
 * /oauth/authorize endpoint — Phase 3.
 *
 * Pre-WP route handler intercepted at init priority 0 by AuthorizationServer.
 * GET handles initial redirect-from-bridge; POST handles consent form submit.
 *
 * Locked-spec compliance:
 *   - Appendix H.3.6: validate client_id + redirect_uri BEFORE the login
 *     redirect. An attacker hitting /oauth/authorize with a malformed
 *     client_id gets a 400 HTML error, NOT a redirect to wp-login.
 *   - Appendix H.3.5: state is required, ≤256 chars, round-tripped opaquely.
 *   - Appendix H.3.4 + sub-issue scope: sensitive scopes always show
 *     consent; auto-approve only when (recognized client_id + unchanged
 *     non-sensitive scopes + within consent_max_silent_days).
 *   - Appendix H.4.5: scope set re-validated server-side on POST against
 *     the rendered nonce; role switcher constrained server-side to roles
 *     the current user actually holds.
 *
 * Output rules (all responses):
 *   - Cache-Control: no-store
 *   - X-Frame-Options: DENY (consent screen is server-rendered, no JS, no iframes)
 *   - No CORS — consent is operator-facing, never cross-origin
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints;

use function WickedEvolutions\McpAdapter\Auth\OAuth\oauth_client_ip;
use function WickedEvolutions\McpAdapter\Auth\OAuth\oauth_log_boundary;
use WickedEvolutions\McpAdapter\Auth\OAuth\AuthorizationCodeStore;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\AuthorizeRequestValidator;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\AuthorizeValidationResult;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\ConsentDecision;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\ConsentDecisionEvaluator;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\ConsentScreenRenderer;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\LastConsentLookup;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\PolicyStore;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\PriorGrantLookup;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\RenderedScopeNonce;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\RoleSelector;
use WickedEvolutions\McpAdapter\Auth\OAuth\DiscoveryEndpoints;

/**
 * Top-level dispatcher for /oauth/authorize. Pre-WP — exits with `never`.
 */
final class AuthorizeEndpoint {

	/** Lifetime of an issued authorization code (seconds). */
	private const CODE_TTL = 600;

	/** Dispatch by request method. */
	public static function dispatch(): never {
		$method = strtoupper( (string) ( $_SERVER['REQUEST_METHOD'] ?? 'GET' ) );
		match ( $method ) {
			'GET'  => self::handle_get( $_GET ),
			'POST' => self::handle_post( $_POST ),
			default => self::reject_method(),
		};
	}

	/** Reject any non-GET / non-POST method per OAuth 2.1. */
	private static function reject_method(): never {
		status_header( 405 );
		header( 'Allow: GET, POST' );
		header( 'Cache-Control: no-store' );
		exit;
	}

	// ─── GET /oauth/authorize ────────────────────────────────────────────────────

	/**
	 * GET handler — validates per H.3.6, then dispatches to login redirect,
	 * auto-approve, or consent screen.
	 *
	 * @param array $params Raw query string.
	 */
	public static function handle_get( array $params ): never {
		$resource_indicator = self::resource_indicator();
		$validation         = AuthorizeRequestValidator::validate( $params, $resource_indicator );

		if ( $validation->is_pre_redirect_error() ) {
			\oauth_log_boundary( 'boundary.oauth_authorize_error', array(
				'ip'         => \oauth_client_ip(),
				'reason'     => 'pre_redirect_validation_failed',
				'error_code' => $validation->error_code,
			) );
			ConsentScreenRenderer::render_error(
				__( 'Authorization request invalid', 'mcp-adapter' ),
				$validation->error_description
			);
		}

		if ( $validation->is_redirectable_error() ) {
			\oauth_log_boundary( 'boundary.oauth_authorize_error', array(
				'client_id'  => (string) $validation->client->client_id,
				'reason'     => 'redirectable_validation_failed',
				'error_code' => $validation->error_code,
			) );
			self::redirect_with_error( $validation->redirect_uri, $validation->error_code, $validation->error_description, $validation->state );
		}

		// Validation passed. From here, the request can be redirected to wp-login safely
		// (the redirect_uri itself is now known good — H.3.6 line 7 reached).
		if ( ! is_user_logged_in() ) {
			self::redirect_to_login();
		}

		$user_id = (int) get_current_user_id();
		$now     = time();

		$prior_scopes      = PriorGrantLookup::scopes_for( (string) $validation->client->client_id, $user_id );
		$last_interactive  = LastConsentLookup::timestamp_for( (string) $validation->client->client_id, $user_id );
		$silent_cap_days   = PolicyStore::consent_max_silent_days();

		$decision = ConsentDecisionEvaluator::evaluate(
			$validation->requested_scopes,
			$prior_scopes,
			$last_interactive,
			$now,
			$silent_cap_days
		);

		if ( $decision->is_auto_approve() ) {
			self::mint_code_and_redirect( $validation, $decision, $user_id, /* interactive */ false );
		}

		// Render full or incremental consent.
		self::render_consent( $validation, $decision, $user_id, $last_interactive );
	}

	/**
	 * Issue a code, log the appropriate boundary event, and 302 to redirect_uri.
	 *
	 * @param bool $interactive True when the operator just clicked Authorize on the consent form.
	 */
	private static function mint_code_and_redirect(
		AuthorizeValidationResult $validation,
		ConsentDecision $decision,
		int $user_id,
		bool $interactive,
		?array $effective_scopes = null
	): never {
		$client_id = (string) $validation->client->client_id;
		$scopes    = $effective_scopes ?? $decision->requested;
		$scope_str = implode( ' ', $scopes );

		$plaintext_code = bin2hex( random_bytes( 32 ) );
		AuthorizationCodeStore::store(
			hash( 'sha256', $plaintext_code ),
			$client_id,
			$user_id,
			$validation->redirect_uri,
			$scope_str,
			$validation->resource,
			$validation->code_challenge,
			self::CODE_TTL
		);

		if ( $interactive ) {
			LastConsentLookup::record( $client_id, $user_id, time() );
			\oauth_log_boundary( 'boundary.oauth_authorization_granted', array(
				'client_id' => $client_id,
				'user_id'   => $user_id,
			) );
		} else {
			\oauth_log_boundary( 'boundary.oauth_authorization_auto_approved', array(
				'client_id' => $client_id,
				'user_id'   => $user_id,
			) );
		}

		self::redirect_with_code( $validation->redirect_uri, $plaintext_code, $validation->state );
	}

	/** Render full or incremental consent screen. */
	private static function render_consent(
		AuthorizeValidationResult $validation,
		ConsentDecision $decision,
		int $user_id,
		?int $last_interactive_unix
	): never {
		$client = $validation->client;
		$user   = function_exists( 'get_userdata' ) ? get_userdata( $user_id ) : null;

		$user_login   = $user && isset( $user->user_login )   ? (string) $user->user_login   : (string) $user_id;
		$user_display = $user && isset( $user->display_name ) ? (string) $user->display_name : $user_login;

		$available_roles = RoleSelector::roles_for_user_id( $user_id );

		$action_url = self::self_url();

		ConsentScreenRenderer::render( array(
			'client_id'                  => (string) $client->client_id,
			'client_name'                => (string) ( $client->client_name ?? '' ),
			'redirect_uri'               => $validation->redirect_uri,
			'scope'                      => implode( ' ', $decision->requested ),
			'state'                      => $validation->state,
			'code_challenge'             => $validation->code_challenge,
			'resource'                   => $validation->resource,
			'user_id'                    => $user_id,
			'user_login'                 => $user_login,
			'user_display'               => $user_display,
			'available_roles'            => $available_roles,
			'decision'                   => $decision,
			'previously_granted_at_unix' => $last_interactive_unix,
			'action_url'                 => $action_url,
		) );
	}

	// ─── POST /oauth/authorize ───────────────────────────────────────────────────

	/**
	 * POST handler — operator submitted the consent form.
	 *
	 * Re-validates query parameters from the POST body (defense-in-depth: never
	 * trust that the GET-validated values survived an attacker-controlled DOM).
	 * Re-checks scope subset against the server-issued nonce (H.4.5).
	 * Re-checks role membership against the user's actual roles (H.4.5).
	 *
	 * @param array $params Raw $_POST.
	 */
	public static function handle_post( array $params ): never {
		// Operator must be logged in to post the consent form.
		if ( ! is_user_logged_in() ) {
			self::redirect_to_login();
		}

		$resource_indicator = self::resource_indicator();
		$validation         = AuthorizeRequestValidator::validate( $params, $resource_indicator );

		if ( $validation->is_pre_redirect_error() ) {
			ConsentScreenRenderer::render_error(
				__( 'Authorization request invalid', 'mcp-adapter' ),
				$validation->error_description
			);
		}
		if ( $validation->is_redirectable_error() ) {
			self::redirect_with_error( $validation->redirect_uri, $validation->error_code, $validation->error_description, $validation->state );
		}

		$user_id = (int) get_current_user_id();
		$client  = $validation->client;

		$decision_field = (string) ( $params[ ConsentScreenRenderer::DECISION_FIELD ] ?? '' );
		if ( ConsentScreenRenderer::DECISION_DENY === $decision_field ) {
			\oauth_log_boundary( 'boundary.oauth_authorization_denied', array(
				'client_id' => (string) $client->client_id,
				'user_id'   => $user_id,
				'reason'    => 'operator_denied',
			) );
			self::redirect_with_error( $validation->redirect_uri, 'access_denied', 'The operator declined to grant access.', $validation->state );
		}

		if ( ConsentScreenRenderer::DECISION_AUTHORIZE !== $decision_field ) {
			ConsentScreenRenderer::render_error(
				__( 'Consent form invalid', 'mcp-adapter' ),
				__( 'No decision was submitted.', 'mcp-adapter' )
			);
		}

		// === H.4.5: redeem the rendered-scope nonce. ===
		$nonce_value = (string) ( $params[ ConsentScreenRenderer::NONCE_FIELD ] ?? '' );
		$payload     = RenderedScopeNonce::redeem( $nonce_value );
		if ( null === $payload ) {
			ConsentScreenRenderer::render_error(
				__( 'Consent form expired', 'mcp-adapter' ),
				__( 'Please restart the authorization flow from your bridge.', 'mcp-adapter' )
			);
		}

		// === H.4.5: scope set re-validation against the server-issued nonce. ===
		$submitted_scopes = self::submitted_scopes( $params );
		if ( ! RenderedScopeNonce::submitted_subset_is_valid(
			$payload,
			$user_id,
			(string) $client->client_id,
			$validation->redirect_uri,
			$validation->state,
			$submitted_scopes
		) ) {
			\oauth_log_boundary( 'boundary.oauth_authorize_error', array(
				'client_id' => (string) $client->client_id,
				'user_id'   => $user_id,
				'reason'    => 'scope_subset_violation',
			) );
			ConsentScreenRenderer::render_error(
				__( 'Consent form tampering detected', 'mcp-adapter' ),
				__( 'The submitted permissions do not match what was rendered. Please restart the authorization flow.', 'mcp-adapter' )
			);
		}

		// === H.4.5: role switcher must be a role the user currently holds. ===
		$submitted_role  = (string) ( $params[ ConsentScreenRenderer::ROLE_FIELD ] ?? '' );
		$available_roles = RoleSelector::roles_for_user_id( $user_id );
		if ( ! empty( $available_roles ) ) {
			// If the form sent any role, it must be one the user actually holds.
			if ( '' !== $submitted_role && ! RoleSelector::user_holds_role( $user_id, $submitted_role ) ) {
				\oauth_log_boundary( 'boundary.oauth_authorize_error', array(
					'client_id' => (string) $client->client_id,
					'user_id'   => $user_id,
					'reason'    => 'role_escalation_attempt',
				) );
				ConsentScreenRenderer::render_error(
					__( 'Role selection invalid', 'mcp-adapter' ),
					__( 'You may only authorize the bridge as a role you already hold.', 'mcp-adapter' )
				);
			}
		}

		// All gates passed. Submitted scope set may be narrower than rendered.
		// We mint with *the submitted set*, not the originally-requested set.
		$decision = new ConsentDecision(
			ConsentDecision::RENDER_FULL,
			$validation->requested_scopes,
			$submitted_scopes,
			array(),
			array(),
			''
		);
		self::mint_code_and_redirect( $validation, $decision, $user_id, /* interactive */ true, $submitted_scopes );
	}

	/**
	 * Extract the submitted scope[] checkbox values, deduplicated, all strings.
	 *
	 * @param array $params $_POST
	 * @return string[]
	 */
	private static function submitted_scopes( array $params ): array {
		$raw = $params[ ConsentScreenRenderer::SCOPE_FIELD ] ?? array();
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $value ) {
			if ( is_string( $value ) && '' !== $value ) {
				$out[] = $value;
			}
		}
		return array_values( array_unique( $out ) );
	}

	// ─── Redirect helpers ────────────────────────────────────────────────────────

	/** Redirect to wp-login.php with `redirect_to` set back to this exact authorize URL (H.3.6 same-origin note). */
	private static function redirect_to_login(): never {
		$self = self::self_url() . ( isset( $_SERVER['QUERY_STRING'] ) && '' !== (string) $_SERVER['QUERY_STRING']
			? '?' . (string) $_SERVER['QUERY_STRING']
			: '' );
		$login_url = function_exists( 'wp_login_url' )
			? wp_login_url( $self )
			: ( DiscoveryEndpoints::issuer() . '/wp-login.php?redirect_to=' . rawurlencode( $self ) );

		status_header( 302 );
		header( 'Location: ' . $login_url );
		header( 'Cache-Control: no-store' );
		exit;
	}

	/**
	 * Redirect with `code` + `state` to a known-good redirect_uri.
	 * Uses raw header() — wp_redirect adds defaults that don't suit a 302
	 * back to a loopback bridge.
	 */
	private static function redirect_with_code( string $redirect_uri, string $code, string $state ): never {
		$separator = ( str_contains( $redirect_uri, '?' ) ) ? '&' : '?';
		$location  = $redirect_uri
			. $separator . 'code=' . rawurlencode( $code )
			. '&state=' . rawurlencode( $state );

		status_header( 302 );
		header( 'Location: ' . $location );
		header( 'Cache-Control: no-store' );
		exit;
	}

	/**
	 * Redirect with `error=...&error_description=...&state=...` to a known-good redirect_uri.
	 * Per OAuth 2.1 §10.7, only used when redirect_uri itself has been validated.
	 */
	private static function redirect_with_error( string $redirect_uri, string $error_code, string $description, string $state ): never {
		$separator = ( str_contains( $redirect_uri, '?' ) ) ? '&' : '?';
		$location  = $redirect_uri
			. $separator . 'error=' . rawurlencode( $error_code )
			. '&error_description=' . rawurlencode( $description )
			. ( '' !== $state ? '&state=' . rawurlencode( $state ) : '' );

		status_header( 302 );
		header( 'Location: ' . $location );
		header( 'Cache-Control: no-store' );
		exit;
	}

	/** The canonical /oauth/authorize URL on this site, for self-posting + redirect_to. */
	private static function self_url(): string {
		return DiscoveryEndpoints::issuer() . '/oauth/authorize';
	}

	/** This site's resource indicator URL (mirrors AuthorizationServer::authenticate_bearer's binding). */
	private static function resource_indicator(): string {
		return function_exists( 'rest_url' )
			? rest_url( 'mcp/mcp-adapter-default-server' )
			: DiscoveryEndpoints::resource_url();
	}
}
