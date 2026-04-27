<?php
/**
 * Server-rendered consent screen.
 *
 * Plain HTML form — no JavaScript. The form posts to the same /oauth/authorize
 * URL with the OAuth flow parameters round-tripped as hidden inputs. The
 * RenderedScopeNonce binds this rendered scope set to the POST submission
 * (Appendix H.4.5 — browser-extension threat).
 *
 * Per Appendix H.3.4:
 *   - All scopes (previously-granted AND newly-requested) render as toggleable checkboxes.
 *   - Previously-granted scopes are pre-checked AND show a "Granted YYYY-MM-DD" badge.
 *   - Sensitive scopes show a lock icon and require explicit re-check (pre-checked but visible).
 *
 * Per Appendix H.4.5: role switcher only lists roles the current user already holds.
 *
 * No inline style="" attributes — all visuals via class names in assets/consent.css.
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
 * Renders the consent HTML page and exits.
 */
final class ConsentScreenRenderer {

	/** Rendered nonce hidden field name. */
	public const NONCE_FIELD = 'mcp_oauth_consent_nonce';

	/** Submitted scope checkbox name. Multiple values arrive as `mcp_oauth_scope[]`. */
	public const SCOPE_FIELD = 'mcp_oauth_scope';

	/** Submitted role select name. */
	public const ROLE_FIELD = 'mcp_oauth_role';

	/** Submitted decision (`authorize` | `deny`). */
	public const DECISION_FIELD = 'mcp_oauth_decision';

	/** Submitted decision values. */
	public const DECISION_AUTHORIZE = 'authorize';
	public const DECISION_DENY      = 'deny';

	/**
	 * Render the consent page and exit.
	 *
	 * @param array $params {
	 *   @type string   $client_id        OAuth client_id (validated).
	 *   @type string   $client_name      Operator-facing client name from DCR.
	 *   @type string   $redirect_uri     Validated redirect_uri.
	 *   @type string   $scope            Original space-separated scope string (round-trip).
	 *   @type string   $state            OAuth state (round-trip).
	 *   @type string   $code_challenge   PKCE challenge (round-trip).
	 *   @type string   $resource         Resource indicator URL (round-trip).
	 *   @type int      $user_id          Currently logged-in user.
	 *   @type string   $user_login       Login name to display.
	 *   @type string   $user_display     Display name to show.
	 *   @type string[] $available_roles  Roles the user actually holds (already filtered).
	 *   @type ConsentDecision $decision  Routing decision (RENDER_FULL or RENDER_INCREMENTAL).
	 *   @type ?int     $previously_granted_at_unix Timestamp of last interactive consent (null = first).
	 *   @type string   $action_url       Where the form posts to (full /oauth/authorize URL).
	 * }
	 */
	public static function render( array $params ): never {
		$html = self::build_html( $params );

		status_header( 200 );
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'Cache-Control: no-store, no-cache, max-age=0' );
		header( 'Pragma: no-cache' );
		header( 'X-Frame-Options: DENY' );
		header( "Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'" );

		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML built by build_html(); all dynamic values escaped at insertion.
		exit;
	}

	/**
	 * Build the consent screen HTML without side effects.
	 *
	 * Same parameter contract as {@see render()}. Returns the HTML body so
	 * tests can assert structure, escape correctness, and nonce embedding
	 * without the `exit` of the production render path.
	 */
	public static function build_html( array $params ): string {
		$client_id      = (string) ( $params['client_id'] ?? '' );
		$client_name    = (string) ( $params['client_name'] ?? __( 'Unnamed bridge', 'mcp-adapter' ) );
		$redirect_uri   = (string) ( $params['redirect_uri'] ?? '' );
		$scope          = (string) ( $params['scope'] ?? '' );
		$state          = (string) ( $params['state'] ?? '' );
		$code_challenge = (string) ( $params['code_challenge'] ?? '' );
		$resource       = (string) ( $params['resource'] ?? '' );
		$user_id        = (int) ( $params['user_id'] ?? 0 );
		$user_login     = (string) ( $params['user_login'] ?? '' );
		$user_display   = (string) ( $params['user_display'] ?? $user_login );
		$available_roles = is_array( $params['available_roles'] ?? null ) ? $params['available_roles'] : array();
		/** @var ConsentDecision $decision */
		$decision = $params['decision'];
		$previously_at = $params['previously_granted_at_unix'] ?? null;
		$action_url    = (string) ( $params['action_url'] ?? '' );
		$site_name     = function_exists( 'get_bloginfo' ) ? (string) get_bloginfo( 'name' ) : '';
		$site_url      = function_exists( 'home_url' ) ? (string) home_url() : '';

		$rendered_scopes = $decision->requested;
		$nonce = RenderedScopeNonce::issue( $rendered_scopes, $user_id, $client_id, $redirect_uri, $state );

		$consent_css_url = self::stylesheet_url();
		$is_incremental  = $decision->is_render_incremental();
		$reason          = $decision->reason;

		ob_start();
		?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?php echo esc_html( sprintf( __( 'Authorize %s', 'mcp-adapter' ), $client_name ) ); ?></title>
<?php if ( $consent_css_url ) : ?>
<link rel="stylesheet" href="<?php echo esc_url( $consent_css_url ); ?>">
<?php endif; ?>
</head>
<body class="wp-mcp-consent-body">
<main class="wp-mcp-consent-shell">
	<header class="wp-mcp-consent-header">
		<h1 class="wp-mcp-consent-h1"><?php echo esc_html( sprintf( __( 'Authorize %s', 'mcp-adapter' ), $client_name ) ); ?></h1>
		<p class="wp-mcp-consent-site">
			<?php echo esc_html( $site_name ); ?>
			<?php if ( $site_url ) : ?>
				<span class="wp-mcp-consent-site-url"><?php echo esc_html( $site_url ); ?></span>
			<?php endif; ?>
		</p>
	</header>

	<?php if ( 'silent_cap_exceeded' === $reason ) : ?>
		<p class="wp-mcp-consent-notice wp-mcp-consent-notice--reauth">
			<?php esc_html_e( 'You have not reviewed this bridge in a while. Please re-confirm what it can access.', 'mcp-adapter' ); ?>
		</p>
	<?php elseif ( $is_incremental ) : ?>
		<p class="wp-mcp-consent-notice wp-mcp-consent-notice--incremental">
			<?php esc_html_e( 'This bridge is requesting additional permissions beyond what you previously granted.', 'mcp-adapter' ); ?>
		</p>
	<?php endif; ?>

	<form method="post" action="<?php echo esc_url( $action_url ); ?>" class="wp-mcp-consent-form">
		<input type="hidden" name="client_id"        value="<?php echo esc_attr( $client_id ); ?>">
		<input type="hidden" name="redirect_uri"     value="<?php echo esc_attr( $redirect_uri ); ?>">
		<input type="hidden" name="scope"            value="<?php echo esc_attr( $scope ); ?>">
		<input type="hidden" name="state"            value="<?php echo esc_attr( $state ); ?>">
		<input type="hidden" name="code_challenge"   value="<?php echo esc_attr( $code_challenge ); ?>">
		<input type="hidden" name="code_challenge_method" value="S256">
		<input type="hidden" name="response_type"    value="code">
		<input type="hidden" name="resource"         value="<?php echo esc_attr( $resource ); ?>">
		<input type="hidden" name="<?php echo esc_attr( self::NONCE_FIELD ); ?>" value="<?php echo esc_attr( $nonce ); ?>">

		<section class="wp-mcp-consent-identity">
			<h2 class="wp-mcp-consent-h2"><?php esc_html_e( 'Authorize as', 'mcp-adapter' ); ?></h2>
			<p class="wp-mcp-consent-user">
				<strong><?php echo esc_html( $user_display ); ?></strong>
				<span class="wp-mcp-consent-user-login">(<?php echo esc_html( $user_login ); ?>)</span>
			</p>
			<?php if ( count( $available_roles ) > 1 ) : ?>
				<label class="wp-mcp-consent-label" for="wp-mcp-consent-role">
					<?php esc_html_e( 'Role to grant:', 'mcp-adapter' ); ?>
				</label>
				<select id="wp-mcp-consent-role" name="<?php echo esc_attr( self::ROLE_FIELD ); ?>" class="wp-mcp-consent-select">
					<?php foreach ( $available_roles as $role ) : ?>
						<option value="<?php echo esc_attr( $role ); ?>"><?php echo esc_html( $role ); ?></option>
					<?php endforeach; ?>
				</select>
			<?php elseif ( count( $available_roles ) === 1 ) : ?>
				<input type="hidden" name="<?php echo esc_attr( self::ROLE_FIELD ); ?>" value="<?php echo esc_attr( $available_roles[0] ); ?>">
				<p class="wp-mcp-consent-hint">
					<?php
					echo esc_html( sprintf(
						/* translators: %s = WordPress role slug */
						__( 'Role: %s', 'mcp-adapter' ),
						$available_roles[0]
					) );
					?>
				</p>
			<?php endif; ?>
		</section>

		<section class="wp-mcp-consent-scopes">
			<h2 class="wp-mcp-consent-h2"><?php esc_html_e( 'Permissions requested', 'mcp-adapter' ); ?></h2>
			<?php self::render_scope_groups( $rendered_scopes, $decision, $previously_at ); ?>
		</section>

		<section class="wp-mcp-consent-actions">
			<button type="submit"
			        name="<?php echo esc_attr( self::DECISION_FIELD ); ?>"
			        value="<?php echo esc_attr( self::DECISION_DENY ); ?>"
			        class="wp-mcp-consent-button wp-mcp-consent-button--secondary">
				<?php esc_html_e( 'Deny', 'mcp-adapter' ); ?>
			</button>
			<button type="submit"
			        name="<?php echo esc_attr( self::DECISION_FIELD ); ?>"
			        value="<?php echo esc_attr( self::DECISION_AUTHORIZE ); ?>"
			        class="wp-mcp-consent-button wp-mcp-consent-button--primary">
				<?php esc_html_e( 'Authorize', 'mcp-adapter' ); ?>
			</button>
		</section>

		<footer class="wp-mcp-consent-footer">
			<p class="wp-mcp-consent-footer-text">
				<?php esc_html_e( 'You can revoke this authorization at any time from the Connected Bridges tab in WP-Admin.', 'mcp-adapter' ); ?>
			</p>
		</footer>
	</form>
</main>
</body>
</html>
		<?php
		return (string) ob_get_clean();
	}

	/**
	 * Render the grouped scope checkbox list.
	 *
	 * @param string[]        $rendered_scopes
	 * @param ConsentDecision $decision
	 * @param ?int            $previously_granted_at_unix
	 */
	private static function render_scope_groups( array $rendered_scopes, ConsentDecision $decision, ?int $previously_granted_at_unix ): void {
		$groups            = ScopeGrouper::group( $rendered_scopes );
		$previously        = array_flip( $decision->previously );
		$granted_date_text = $previously_granted_at_unix
			? gmdate( 'Y-m-d', $previously_granted_at_unix )
			: '';

		foreach ( $groups as $module => $scopes ) {
			$module_label = 'umbrella' === $module
				? __( 'Umbrella permissions', 'mcp-adapter' )
				: ucfirst( str_replace( '-', ' ', (string) $module ) );
			$is_sensitive_group = ScopeGrouper::group_is_sensitive( $scopes );
			?>
			<fieldset class="wp-mcp-consent-group <?php echo $is_sensitive_group ? 'wp-mcp-consent-group--sensitive' : ''; ?>">
				<legend class="wp-mcp-consent-legend">
					<?php echo esc_html( $module_label ); ?>
					<?php if ( $is_sensitive_group ) : ?>
						<span class="wp-mcp-consent-lock" aria-label="<?php esc_attr_e( 'Sensitive permission', 'mcp-adapter' ); ?>">&#x1F512;</span>
					<?php endif; ?>
				</legend>
				<?php foreach ( $scopes as $scope_name ) :
					$is_sensitive = ScopeRegistry::is_sensitive( $scope_name );
					$was_granted  = isset( $previously[ $scope_name ] );
					// All scopes pre-checked, all toggleable. Sensitive scopes always rendered (per H.3.4).
					?>
					<label class="wp-mcp-consent-scope <?php echo $is_sensitive ? 'wp-mcp-consent-scope--sensitive' : ''; ?>">
						<input type="checkbox"
						       name="<?php echo esc_attr( self::SCOPE_FIELD ); ?>[]"
						       value="<?php echo esc_attr( $scope_name ); ?>"
						       checked>
						<span class="wp-mcp-consent-scope-name"><?php echo esc_html( $scope_name ); ?></span>
						<?php if ( $was_granted && '' !== $granted_date_text ) : ?>
							<span class="wp-mcp-consent-badge wp-mcp-consent-badge--granted">
								<?php
								echo esc_html( sprintf(
									/* translators: %s = ISO date YYYY-MM-DD */
									__( 'Granted %s', 'mcp-adapter' ),
									$granted_date_text
								) );
								?>
							</span>
						<?php endif; ?>
						<?php if ( $is_sensitive ) : ?>
							<span class="wp-mcp-consent-badge wp-mcp-consent-badge--sensitive">
								<?php esc_html_e( 'Sensitive', 'mcp-adapter' ); ?>
							</span>
						<?php endif; ?>
					</label>
				<?php endforeach; ?>
			</fieldset>
			<?php
		}
	}

	/**
	 * Resolve the URL of consent.css. Returns empty string if asset machinery is unavailable.
	 */
	private static function stylesheet_url(): string {
		if ( ! function_exists( 'plugins_url' ) || ! defined( 'ABILITIES_MCP_ADAPTER_PATH' ) ) {
			return '';
		}
		$ver = defined( 'ABILITIES_MCP_ADAPTER_VERSION' ) ? '?v=' . rawurlencode( (string) ABILITIES_MCP_ADAPTER_VERSION ) : '';
		return plugins_url( 'assets/consent.css', ABILITIES_MCP_ADAPTER_PATH . 'abilities-mcp-adapter.php' ) . $ver;
	}

	/**
	 * Render an error page for pre-login validation failures (Appendix H.3.6).
	 * No redirect — pure 400 HTML so the request never leaks into wp-login.
	 */
	public static function render_error( string $title, string $detail, int $status = 400 ): never {
		$html = self::build_error_html( $title, $detail );

		status_header( $status );
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'Cache-Control: no-store, no-cache, max-age=0' );
		header( 'Pragma: no-cache' );
		header( 'X-Frame-Options: DENY' );

		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Built by build_error_html(), all dynamic values escaped.
		exit;
	}

	/**
	 * Build the error page HTML without side effects. Tested independently.
	 */
	public static function build_error_html( string $title, string $detail ): string {
		$consent_css_url = self::stylesheet_url();
		ob_start();
		?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?php echo esc_html( $title ); ?></title>
<?php if ( $consent_css_url ) : ?>
<link rel="stylesheet" href="<?php echo esc_url( $consent_css_url ); ?>">
<?php endif; ?>
</head>
<body class="wp-mcp-consent-body">
<main class="wp-mcp-consent-shell wp-mcp-consent-shell--error">
	<h1 class="wp-mcp-consent-h1"><?php echo esc_html( $title ); ?></h1>
	<p class="wp-mcp-consent-error"><?php echo esc_html( $detail ); ?></p>
	<p class="wp-mcp-consent-footer-text">
		<?php esc_html_e( 'No authorization has been granted. You can safely close this tab.', 'mcp-adapter' ); ?>
	</p>
</main>
</body>
</html>
		<?php
		return (string) ob_get_clean();
	}
}
