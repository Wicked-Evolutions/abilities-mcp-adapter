<?php
/**
 * OAuth 2.1 Authorization Server — top-level coordinator.
 *
 * Registers:
 * - DB schema migration (four kl_oauth_* tables, InnoDB)
 * - Pre-WP discovery route interception (init priority 0)
 * - REST endpoints (register, token, revoke)
 * - Bearer token validation (determine_current_user priority 20)
 * - OAuthHostAllowlist build at plugins_loaded
 *
 * Global helper functions defined here (in this file's namespace) to avoid
 * polluting plugin's primary namespace:
 *   oauth_client_ip()       — trusted-proxy-aware client IP
 *   oauth_is_https()        — scheme detection (H.2.5)
 *   oauth_read_auth_header() — Authorization header recovery (H.2.6)
 *   oauth_log_boundary()    — metadata-only boundary event (H.4.3)
 *   token_error()           — RFC 6749 §5.2 error response (H.3.7)
 *   token_success()         — RFC 6749 §5.1 success response (H.3.7)
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Auth\OAuth;

use WickedEvolutions\McpAdapter\Admin\Bridges\AuthHeaderProbe;
use WickedEvolutions\McpAdapter\Admin\Bridges\BoundaryAuditBuffer;
use WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints\AuthorizeEndpoint;
use WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints\RegisterEndpoint;
use WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints\TokenEndpoint;
use WickedEvolutions\McpAdapter\Auth\OAuth\Endpoints\RevokeEndpoint;

/**
 * Boot and coordinate the OAuth 2.1 authorization server.
 */
final class AuthorizationServer {

	/** REST namespace shared with the MCP adapter. */
	private const REST_NS = 'mcp';

	private static bool $booted = false;

	/** Register all WordPress hooks. Called once from the main plugin file. */
	public static function boot(): void {
		if ( self::$booted ) {
			return;
		}
		self::$booted = true;

		// Build host allowlist at plugins_loaded (multisite blogs table available).
		add_action( 'plugins_loaded', [ OAuthHostAllowlist::class, 'build' ], 5 );

		// DB schema migration.
		add_action( 'plugins_loaded', [ self::class, 'maybe_run_migration' ], 10 );

		// Pre-WP route interception for .well-known and /oauth/authorize.
		add_action( 'init', [ self::class, 'intercept_pre_wp_routes' ], 0 );

		// REST routes for DCR, token, revoke.
		add_action( 'rest_api_init', [ self::class, 'register_rest_routes' ] );

		// Bearer token authentication (priority 20 — after WP core's auth).
		add_filter( 'determine_current_user', [ self::class, 'authenticate_bearer' ], 20 );

		// Reset OAuthRequestContext at the start of each REST request.
		add_action( 'rest_api_init', [ OAuthRequestContext::class, 'reset' ], 1 );

		// Phase 3: capture OAuth boundary events for the Connected Bridges audit slice.
		BoundaryAuditBuffer::register();

		// Phase 3: provide a data source for the H.2.6 Authorization-header diagnostic.
		AuthHeaderProbe::register();
	}

	/** Run DB migration if schema version has changed. */
	public static function maybe_run_migration(): void {
		$version_key = 'abilities_oauth_db_version';
		$current     = '1.0.0';

		if ( get_option( $version_key ) === $current ) {
			return;
		}

		self::run_migration();
		update_option( $version_key, $current );
	}

	/** Create or update the four kl_oauth_* tables via dbDelta(). Idempotent. */
	public static function run_migration(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$p       = $wpdb->prefix;

		dbDelta( "CREATE TABLE `{$p}kl_oauth_clients` (
			id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			client_id        VARCHAR(128)    NOT NULL,
			client_name      VARCHAR(255)    NOT NULL DEFAULT '',
			redirect_uris    TEXT            NOT NULL,
			software_id      VARCHAR(128)    NOT NULL DEFAULT '',
			software_version VARCHAR(32)     NOT NULL DEFAULT '',
			scopes           TEXT            NOT NULL DEFAULT '',
			registered_ip    VARCHAR(45)     NOT NULL DEFAULT '',
			registered_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
			revoked_at       DATETIME                 DEFAULT NULL,
			PRIMARY KEY (id),
			UNIQUE KEY client_id (client_id)
		) {$charset} ENGINE=InnoDB;" );

		dbDelta( "CREATE TABLE `{$p}kl_oauth_codes` (
			id                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			code_hash             VARCHAR(64)     NOT NULL,
			client_id             VARCHAR(128)    NOT NULL,
			user_id               BIGINT UNSIGNED NOT NULL,
			redirect_uri          VARCHAR(2048)   NOT NULL DEFAULT '',
			scope                 TEXT            NOT NULL DEFAULT '',
			resource              VARCHAR(2048)   NOT NULL DEFAULT '',
			code_challenge        VARCHAR(128)    NOT NULL,
			code_challenge_method VARCHAR(8)      NOT NULL DEFAULT 'S256',
			expires_at            DATETIME        NOT NULL,
			used                  TINYINT(1)      NOT NULL DEFAULT 0,
			created_at            DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY code_hash (code_hash),
			KEY client_id (client_id)
		) {$charset} ENGINE=InnoDB;" );

		dbDelta( "CREATE TABLE `{$p}kl_oauth_tokens` (
			id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			token_hash   VARCHAR(64)     NOT NULL,
			client_id    VARCHAR(128)    NOT NULL,
			user_id      BIGINT UNSIGNED NOT NULL,
			scope        TEXT            NOT NULL DEFAULT '',
			resource     VARCHAR(2048)   NOT NULL DEFAULT '',
			token_type   VARCHAR(16)     NOT NULL DEFAULT 'Bearer',
			expires_at   DATETIME        NOT NULL,
			revoked      TINYINT(1)      NOT NULL DEFAULT 0,
			last_used_at DATETIME                 DEFAULT NULL,
			created_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY token_hash (token_hash),
			KEY client_id (client_id)
		) {$charset} ENGINE=InnoDB;" );

		dbDelta( "CREATE TABLE `{$p}kl_oauth_refresh_tokens` (
			id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			token_hash       VARCHAR(64)     NOT NULL,
			access_token_id  BIGINT UNSIGNED NOT NULL,
			client_id        VARCHAR(128)    NOT NULL,
			user_id          BIGINT UNSIGNED NOT NULL,
			scope            TEXT            NOT NULL DEFAULT '',
			resource         VARCHAR(2048)   NOT NULL DEFAULT '',
			family_id        VARCHAR(64)     NOT NULL,
			expires_at       DATETIME        NOT NULL,
			revoked          TINYINT(1)      NOT NULL DEFAULT 0,
			rotated_at       DATETIME                 DEFAULT NULL,
			rotated_to_hash  VARCHAR(64)              DEFAULT NULL,
			created_at       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY token_hash (token_hash),
			KEY client_id (client_id),
			KEY family_id_revoked (family_id, revoked)
		) {$charset} ENGINE=InnoDB;" );
	}

	/** Pre-WP init priority 0: intercept .well-known and /oauth/authorize. */
	public static function intercept_pre_wp_routes(): void {
		$host = $_SERVER['HTTP_HOST'] ?? '';
		if ( ! OAuthHostAllowlist::is_allowed( $host ) ) {
			// Unknown host — log and 404. Do not serve OAuth metadata.
			if ( self::is_well_known_or_oauth_path() ) {
				oauth_log_boundary( 'boundary.oauth_host_rejected', [ 'ip' => oauth_client_ip() ] );
				status_header( 404 );
				exit;
			}
			return;
		}

		$path = strtok( $_SERVER['REQUEST_URI'] ?? '', '?' );

		match ( $path ) {
			'/.well-known/oauth-protected-resource'  => DiscoveryEndpoints::serve_protected_resource(),
			'/.well-known/oauth-authorization-server'=> DiscoveryEndpoints::serve_authorization_server(),
			'/.well-known/openid-configuration'      => DiscoveryEndpoints::serve_oidc_configuration(),
			'/oauth/authorize'                       => AuthorizeEndpoint::dispatch(),
			default => null,
		};
	}

	private static function is_well_known_or_oauth_path(): bool {
		$path = strtok( $_SERVER['REQUEST_URI'] ?? '', '?' );
		return str_starts_with( $path, '/.well-known/' ) || str_starts_with( $path, '/oauth/' );
	}

	/** Register REST routes for DCR, token, revoke. */
	public static function register_rest_routes(): void {
		$ns = self::REST_NS;

		register_rest_route( $ns, '/oauth/register', [
			[
				'methods'             => 'GET',
				'callback'            => [ RegisterEndpoint::class, 'handle_get' ],
				'permission_callback' => '__return_true',
			],
			[
				'methods'             => 'POST',
				'callback'            => [ RegisterEndpoint::class, 'handle_post' ],
				'permission_callback' => '__return_true',
			],
		] );

		register_rest_route( $ns, '/oauth/token', [
			[
				'methods'             => 'GET',
				'callback'            => [ TokenEndpoint::class, 'handle_get' ],
				'permission_callback' => '__return_true',
			],
			[
				'methods'             => 'POST',
				'callback'            => [ TokenEndpoint::class, 'handle_post' ],
				'permission_callback' => '__return_true',
			],
		] );

		register_rest_route( $ns, '/oauth/revoke', [
			[
				'methods'             => 'GET',
				'callback'            => [ RevokeEndpoint::class, 'handle_get' ],
				'permission_callback' => '__return_true',
			],
			[
				'methods'             => 'POST',
				'callback'            => [ RevokeEndpoint::class, 'handle_post' ],
				'permission_callback' => '__return_true',
			],
		] );
	}

	/**
	 * Bearer token authentication hook (determine_current_user, priority 20).
	 *
	 * If no user is resolved yet and an OAuth Bearer token is present:
	 * - Validates token (not expired, not revoked, resource matches)
	 * - Sets OAuthRequestContext with user_id, scopes, resource, client_id, token_id
	 * - Returns user_id to WordPress
	 * - On failure: sets WWW-Authenticate header on the response (H.2.7)
	 *
	 * @param int|false $user_id Already-resolved user_id, or false/0.
	 * @return int|false
	 */
	public static function authenticate_bearer( int|false $user_id ): int|false {
		if ( $user_id ) {
			return $user_id; // Already authenticated by a higher-priority method.
		}
		if ( ! defined( 'REST_REQUEST' ) || ! REST_REQUEST ) {
			return $user_id;
		}

		$auth_header = oauth_read_auth_header();

		// Phase 3 (H.2.6): record header presence/absence for the diagnostic.
		// Only count requests that actually look like MCP traffic so the rolling
		// counter reflects bridge calls, not unrelated REST hits.
		$path = (string) ( $_SERVER['REQUEST_URI'] ?? '' );
		if ( str_contains( $path, '/wp-json/mcp/' ) || str_contains( $path, '/wp-json/abilities-mcp-adapter/' ) ) {
			AuthHeaderProbe::record( null !== $auth_header && '' !== $auth_header );
		}

		if ( ! $auth_header || ! str_starts_with( $auth_header, 'Bearer ' ) ) {
			return $user_id;
		}

		$bearer_token = substr( $auth_header, 7 );
		if ( ! $bearer_token ) {
			return $user_id;
		}

		$row = TokenStore::lookup_access_token( $bearer_token );

		if ( ! $row ) {
			// Token not found — set WWW-Authenticate for discovery (H.2.7).
			// Do not differentiate "not found" from "expired" to the client.
			self::schedule_www_authenticate( 'invalid_token', 'The access token is invalid.' );
			oauth_log_boundary( 'boundary.oauth_invalid_token', [ 'ip' => oauth_client_ip(), 'reason' => 'not_found_or_expired' ] );
			return $user_id;
		}

		if ( $row->revoked ) {
			self::schedule_www_authenticate( 'invalid_token', 'The access token has been revoked.' );
			oauth_log_boundary( 'boundary.oauth_invalid_token', [ 'client_id' => $row->client_id, 'reason' => 'revoked' ] );
			return $user_id;
		}

		// Timezone-safe expiry check (H.2.7).
		$expires = \DateTimeImmutable::createFromFormat( 'Y-m-d H:i:s', $row->expires_at, new \DateTimeZone( 'UTC' ) );
		if ( $expires < new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) ) ) {
			// Expired — same response as not-found (H.2.7: no differential).
			self::schedule_www_authenticate( 'invalid_token', 'The access token is invalid.' );
			oauth_log_boundary( 'boundary.oauth_invalid_token', [ 'client_id' => $row->client_id, 'reason' => 'not_found_or_expired' ] );
			return $user_id;
		}

		// Resource indicator validation (H.1.2) — token must be bound to this site's MCP endpoint.
		$current_resource = rest_url( 'mcp/mcp-adapter-default-server' );
		if ( ! hash_equals( (string) $row->resource, $current_resource ) ) {
			self::schedule_www_authenticate( 'invalid_token', 'The access token is invalid.' );
			oauth_log_boundary( 'boundary.oauth_invalid_token', [ 'client_id' => $row->client_id, 'reason' => 'resource_mismatch' ] );
			return $user_id;
		}

		// All checks passed — populate OAuthRequestContext (H.1.3).
		$scopes = array_filter( explode( ' ', (string) $row->scope ) );
		OAuthRequestContext::set(
			(int) $row->user_id,
			$scopes,
			(string) $row->resource,
			(string) $row->client_id,
			(int) $row->id
		);

		// Update last_used_at (fire-and-forget).
		TokenStore::touch( (string) $row->token_hash );

		oauth_log_boundary( 'boundary.oauth_token_validated', [
			'client_id' => $row->client_id,
			'user_id'   => (int) $row->user_id,
		] );

		return (int) $row->user_id;
	}

	/**
	 * Schedule a WWW-Authenticate header for the next response.
	 * Uses rest_post_dispatch to add the header after WP REST routing completes.
	 */
	private static function schedule_www_authenticate( string $error_code, string $description ): void {
		add_filter( 'rest_post_dispatch', static function ( $result ) use ( $error_code, $description ) {
			$issuer  = function_exists( 'home_url' ) ? home_url() : '';
			$meta_url = $issuer . '/.well-known/oauth-protected-resource';
			header( sprintf(
				'WWW-Authenticate: Bearer realm="abilities-mcp", resource_metadata="%s", error="%s", error_description="%s"',
				esc_attr( $meta_url ),
				esc_attr( $error_code ),
				esc_attr( $description )
			) );
			return $result;
		}, 10 );
	}
}

// ─── Global helper functions ───────────────────────────────────────────────────
// Defined in the global namespace so they are accessible from all endpoint classes
// without import. Thin wrappers with no business logic.

if ( ! function_exists( 'oauth_client_ip' ) ) {
	/**
	 * Return the client IP, respecting trusted proxy headers only when
	 * WP_OAUTH_TRUST_FORWARDED_HOST is defined and true (H.2.5).
	 */
	function oauth_client_ip(): string {
		if ( defined( 'WP_OAUTH_TRUST_FORWARDED_HOST' ) && WP_OAUTH_TRUST_FORWARDED_HOST ) {
			$forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
			if ( $forwarded ) {
				return trim( explode( ',', $forwarded )[0] );
			}
		}
		return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
	}
}

if ( ! function_exists( 'oauth_is_https' ) ) {
	/**
	 * Determine whether the current request is HTTPS (H.2.5).
	 * Respects WP's is_ssl() and optionally X-Forwarded-Proto.
	 */
	function oauth_is_https(): bool {
		if ( function_exists( 'is_ssl' ) && is_ssl() ) {
			return true;
		}
		if ( defined( 'WP_OAUTH_TRUST_FORWARDED_HOST' ) && WP_OAUTH_TRUST_FORWARDED_HOST ) {
			return ( $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '' ) === 'https';
		}
		return false;
	}
}

if ( ! function_exists( 'oauth_read_auth_header' ) ) {
	/**
	 * Read the Authorization header with fallbacks for FastCGI/PHP-FPM (H.2.6).
	 *
	 * Order: apache_request_headers() → getallheaders() → $_SERVER['HTTP_AUTHORIZATION']
	 *        → $_SERVER['REDIRECT_HTTP_AUTHORIZATION'].
	 */
	function oauth_read_auth_header(): ?string {
		if ( function_exists( 'apache_request_headers' ) ) {
			foreach ( apache_request_headers() as $k => $v ) {
				if ( strtolower( $k ) === 'authorization' ) {
					return $v;
				}
			}
		}
		if ( function_exists( 'getallheaders' ) ) {
			foreach ( getallheaders() as $k => $v ) {
				if ( strtolower( $k ) === 'authorization' ) {
					return $v;
				}
			}
		}
		return $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null;
	}
}

if ( ! function_exists( 'oauth_log_boundary' ) ) {
	/**
	 * Emit an OAuth event to the boundary log.
	 * Metadata only — never logs token values, hashes, codes, or redirect URLs (H.4.3).
	 *
	 * @param string $event  Must start with 'boundary.oauth_'.
	 * @param array  $tags   Allowlisted metadata fields only.
	 */
	function oauth_log_boundary( string $event, array $tags = [] ): void {
		// Delegate to the BoundaryEventEmitter if available; otherwise fire the action directly.
		if ( function_exists( 'do_action' ) ) {
			do_action( 'mcp_adapter_boundary_event', $event, $tags, null );
		}
	}
}

if ( ! function_exists( 'token_error' ) ) {
	/**
	 * Emit a token endpoint error response per RFC 6749 §5.2 and exit (H.3.7).
	 * Cache-Control: no-store. No CORS. No WP_REST_Response defaults.
	 *
	 * @param string $error       RFC 6749 error code.
	 * @param string $description Human-readable description.
	 * @param int    $status      HTTP status (400 default; 401 for invalid_client).
	 */
	function token_error( string $error, string $description, int $status = 400 ): never {
		status_header( $status );
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Cache-Control: no-store, no-cache, max-age=0' );
		header( 'Pragma: no-cache' );
		// No Access-Control-Allow-Origin (H.4.4).
		echo wp_json_encode( [ 'error' => $error, 'error_description' => $description ] );
		exit;
	}
}

if ( ! function_exists( 'token_success' ) ) {
	/**
	 * Emit a token endpoint success response per RFC 6749 §5.1 and exit (H.3.7).
	 *
	 * @param array $body Response body.
	 * @param int   $status HTTP status (200 default; 201 for DCR).
	 */
	function token_success( array $body, int $status = 200 ): never {
		status_header( $status );
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Cache-Control: no-store, no-cache, max-age=0' );
		header( 'Pragma: no-cache' );
		echo wp_json_encode( $body, JSON_UNESCAPED_SLASHES );
		exit;
	}
}
