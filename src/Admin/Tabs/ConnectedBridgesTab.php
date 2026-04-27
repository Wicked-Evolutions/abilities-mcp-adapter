<?php
/**
 * Connected Bridges admin tab — Phase 3.
 *
 * Lists OAuth-registered bridges, their authorized user, granted scopes,
 * last use / expiry, and last interactive consent age (Appendix H.2.4).
 * Shows the H.2.6 Authorization-header diagnostic. Renders a recent OAuth
 * audit slice so the operator can verify activity at a glance.
 *
 * Revoke uses {@see ClientRegistry::revoke()} which already does the
 * cascade-revoke transaction Phase 1 shipped — propagation is zero-delay
 * because token lookups (per H.1.2 / H.2.7) bypass the object cache.
 *
 * The diagnostic seam (`mcp_adapter_bridges_authorization_header_status`)
 * shipped in Phase 2 is preserved unchanged — Phase 3 just provides a
 * data source via {@see AuthHeaderProbe}.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Admin\Tabs;

// oauth_log_boundary lives in the global namespace (src/Auth/OAuth/helpers.php).
use WickedEvolutions\McpAdapter\Admin\AdapterAdminPage;
use WickedEvolutions\McpAdapter\Admin\Bridges\BoundaryAuditBuffer;
use WickedEvolutions\McpAdapter\Admin\Bridges\BridgeRowProjector;
use WickedEvolutions\McpAdapter\Auth\OAuth\ClientRegistry;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\LastConsentLookup;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\PolicyStore;

/**
 * Renders the Connected Bridges tab and handles its form actions.
 */
final class ConnectedBridgesTab {

	/** Filter hook reserved for the H.2.6 Authorization-header diagnostic. */
	public const DIAGNOSTIC_FILTER = 'mcp_adapter_bridges_authorization_header_status';

	/** POST field marking a bridges-tab action submission. */
	public const ACTION_FIELD = 'mcp_bridges_action';

	/** Nonce action / field. */
	public const NONCE_ACTION = 'mcp_bridges_action';
	public const NONCE_FIELD  = 'mcp_bridges_nonce';

	/** Action values. */
	public const ACTION_REVOKE = 'revoke';

	/**
	 * Render the tab body.
	 */
	public static function render(): void {
		// Operator may have just performed a revoke — surface the result.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only flash query arg
		$flash = isset( $_GET['mcp_bridges_flash'] ) ? sanitize_key( wp_unslash( (string) $_GET['mcp_bridges_flash'] ) ) : '';
		if ( '' !== $flash ) {
			self::render_flash( $flash );
		}

		$clients = ClientRegistry::list_active( 100, 0 );

		if ( empty( $clients ) ) {
			?>
			<p><?php esc_html_e( 'No bridges have completed the OAuth authorization flow yet.', 'mcp-adapter' ); ?></p>

			<div class="wp-mcp-adapter-empty-state">
				<p class="wp-mcp-adapter-empty-state-title"><?php esc_html_e( 'No bridges yet', 'mcp-adapter' ); ?></p>
				<p>
					<?php esc_html_e( 'When a bridge completes the OAuth authorization flow, it will appear here with the user it acts on behalf of, the scopes it requested, and a revoke action.', 'mcp-adapter' ); ?>
				</p>
			</div>
			<?php
		} else {
			self::render_table( $clients );
		}

		self::render_audit_slice();
		self::render_authorization_header_diagnostic();
	}

	/**
	 * Render the bridges table.
	 *
	 * @param object[] $clients
	 */
	private static function render_table( array $clients ): void {
		$silent_cap = PolicyStore::consent_max_silent_days();
		$now        = time();
		$revoke_url = AdapterAdminPage::tab_url( AdapterAdminPage::TAB_BRIDGES );
		?>
		<h2><?php esc_html_e( 'Authorized bridges', 'mcp-adapter' ); ?></h2>
		<table class="widefat striped wp-mcp-adapter-table wp-mcp-bridges-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Bridge', 'mcp-adapter' ); ?></th>
					<th><?php esc_html_e( 'User', 'mcp-adapter' ); ?></th>
					<th><?php esc_html_e( 'Scopes', 'mcp-adapter' ); ?></th>
					<th><?php esc_html_e( 'Last used', 'mcp-adapter' ); ?></th>
					<th><?php esc_html_e( 'Expires', 'mcp-adapter' ); ?></th>
					<th><?php esc_html_e( 'Last consent', 'mcp-adapter' ); ?></th>
					<th class="wp-mcp-adapter-col-action"><?php esc_html_e( 'Action', 'mcp-adapter' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $clients as $client ) :
				$latest_token = self::latest_token_for( (string) $client->client_id );
				$last_consent = LastConsentLookup::timestamp_for( (string) $client->client_id, (int) ( $latest_token->user_id ?? 0 ) );
				$row          = BridgeRowProjector::project( $client, $latest_token, $last_consent, $now, $silent_cap );
				$user_login   = self::user_login( $row['user_id'] );
				?>
				<tr>
					<td>
						<strong><?php echo esc_html( '' !== $row['client_name'] ? $row['client_name'] : __( 'Unnamed bridge', 'mcp-adapter' ) ); ?></strong>
						<?php if ( '' !== $row['software'] ) : ?>
							<br><span class="wp-mcp-adapter-hint"><?php echo esc_html( $row['software'] ); ?></span>
						<?php endif; ?>
					</td>
					<td>
						<?php if ( $row['user_id'] > 0 ) : ?>
							<?php echo esc_html( '' !== $user_login ? $user_login : '#' . $row['user_id'] ); ?>
						<?php else : ?>
							<span class="wp-mcp-adapter-hint"><?php esc_html_e( 'No active token', 'mcp-adapter' ); ?></span>
						<?php endif; ?>
					</td>
					<td>
						<?php if ( ! empty( $row['scopes'] ) ) : ?>
							<ul class="wp-mcp-bridges-scope-list">
								<?php foreach ( $row['scopes'] as $scope ) : ?>
									<li><code><?php echo esc_html( $scope ); ?></code></li>
								<?php endforeach; ?>
							</ul>
						<?php else : ?>
							<span class="wp-mcp-adapter-hint">&mdash;</span>
						<?php endif; ?>
					</td>
					<td><?php echo esc_html( self::format_datetime( $row['last_used_at'] ) ); ?></td>
					<td><?php echo esc_html( self::format_datetime( $row['expires_at'] ) ); ?></td>
					<td>
						<?php if ( null === $row['last_consent_days'] ) : ?>
							<span class="wp-mcp-adapter-hint"><?php esc_html_e( 'Never', 'mcp-adapter' ); ?></span>
						<?php else : ?>
							<?php
							echo esc_html( sprintf(
								/* translators: %d = number of days */
								_n( '%d day ago', '%d days ago', (int) $row['last_consent_days'], 'mcp-adapter' ),
								(int) $row['last_consent_days']
							) );
							?>
							<?php if ( $row['show_silent_warning'] ) : ?>
								<span class="wp-mcp-bridges-warning" title="<?php esc_attr_e( 'Within 30 days of the silent-consent cap. Bridge will require re-confirmation soon.', 'mcp-adapter' ); ?>">&#9888;</span>
							<?php endif; ?>
						<?php endif; ?>
					</td>
					<td>
						<form method="post" action="<?php echo esc_url( $revoke_url ); ?>" class="wp-mcp-adapter-row-form">
							<?php wp_nonce_field( self::NONCE_ACTION, self::NONCE_FIELD ); ?>
							<input type="hidden" name="<?php echo esc_attr( self::ACTION_FIELD ); ?>" value="<?php echo esc_attr( self::ACTION_REVOKE ); ?>">
							<input type="hidden" name="client_id" value="<?php echo esc_attr( $row['client_id'] ); ?>">
							<button type="submit" class="button button-secondary wp-mcp-adapter-row-button"
							        onclick="return confirm('<?php echo esc_js( __( 'Revoke this bridge? All its tokens will be invalidated immediately.', 'mcp-adapter' ) ); ?>');">
								<?php esc_html_e( 'Revoke', 'mcp-adapter' ); ?>
							</button>
						</form>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<p class="wp-mcp-adapter-hint wp-mcp-adapter-hint--spaced">
			<?php
			echo esc_html( sprintf(
				/* translators: %d = days */
				__( 'Bridges that have not interactively re-consented within %d days will be required to show the full consent screen on next authorize.', 'mcp-adapter' ),
				$silent_cap
			) );
			?>
		</p>
		<?php
	}

	/** Render recent OAuth audit slice. */
	private static function render_audit_slice(): void {
		$entries = BoundaryAuditBuffer::read();
		?>
		<h2 class="wp-mcp-adapter-section-spaced"><?php esc_html_e( 'Recent OAuth activity', 'mcp-adapter' ); ?></h2>
		<?php if ( empty( $entries ) ) : ?>
			<p class="wp-mcp-adapter-hint"><?php esc_html_e( 'No OAuth events recorded yet.', 'mcp-adapter' ); ?></p>
			<?php return; ?>
		<?php endif; ?>
		<table class="widefat striped wp-mcp-adapter-table wp-mcp-bridges-audit">
			<thead>
				<tr>
					<th><?php esc_html_e( 'When', 'mcp-adapter' ); ?></th>
					<th><?php esc_html_e( 'Event', 'mcp-adapter' ); ?></th>
					<th><?php esc_html_e( 'Bridge', 'mcp-adapter' ); ?></th>
					<th><?php esc_html_e( 'User', 'mcp-adapter' ); ?></th>
					<th><?php esc_html_e( 'Detail', 'mcp-adapter' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( array_reverse( $entries ) as $entry ) : ?>
				<tr>
					<td><?php echo esc_html( self::format_datetime( gmdate( 'Y-m-d H:i:s', $entry['time'] ) ) ); ?></td>
					<td><code><?php echo esc_html( $entry['event'] ); ?></code></td>
					<td>
						<?php
						echo '' !== $entry['client_id']
							? '<code>' . esc_html( substr( $entry['client_id'], 0, 8 ) ) . '…</code>'
							: '<span class="wp-mcp-adapter-hint">&mdash;</span>';
						?>
					</td>
					<td>
						<?php
						echo $entry['user_id'] > 0
							? '#' . esc_html( (string) $entry['user_id'] )
							: '<span class="wp-mcp-adapter-hint">&mdash;</span>';
						?>
					</td>
					<td>
						<?php if ( '' !== $entry['error_code'] ) : ?>
							<code><?php echo esc_html( $entry['error_code'] ); ?></code>
						<?php elseif ( '' !== $entry['reason'] ) : ?>
							<?php echo esc_html( $entry['reason'] ); ?>
						<?php else : ?>
							<span class="wp-mcp-adapter-hint">&mdash;</span>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<p class="wp-mcp-adapter-hint">
			<?php
			echo esc_html( sprintf(
				/* translators: %d = number of entries */
				_n( 'Last %d OAuth event.', 'Last %d OAuth events.', count( $entries ), 'mcp-adapter' ),
				count( $entries )
			) );
			?>
		</p>
		<?php
	}

	/**
	 * Render the Authorization-header diagnostic card.
	 *
	 * Per H.2.6 the Connected Bridges tab must reserve a hook for this
	 * diagnostic. Phase 2 shipped the seam; Phase 3 ships a data source via
	 * {@see AuthHeaderProbe}, but the seam still works for any third-party
	 * listener that wants to override the value.
	 */
	private static function render_authorization_header_diagnostic(): void {
		$status = self::resolve_status();

		$dot_class   = 'wp-mcp-adapter-status-dot--' . $status['state'];
		$label_class = 'ok' === $status['state'] || 'warn' === $status['state']
			? 'wp-mcp-adapter-status-label--' . $status['state']
			: '';

		$state_labels = array(
			'ok'      => __( 'Detected', 'mcp-adapter' ),
			'warn'    => __( 'Missing', 'mcp-adapter' ),
			'unknown' => __( 'Unknown', 'mcp-adapter' ),
		);
		$state_label = $state_labels[ $status['state'] ] ?? $state_labels['unknown'];

		?>
		<h2 class="wp-mcp-adapter-section-spaced"><?php esc_html_e( 'Authorization header diagnostic', 'mcp-adapter' ); ?></h2>
		<div class="wp-mcp-adapter-card">
			<div class="wp-mcp-adapter-status">
				<span class="wp-mcp-adapter-status-dot <?php echo esc_attr( $dot_class ); ?>"></span>
				<strong class="<?php echo esc_attr( $label_class ); ?>">
					<?php echo esc_html( $state_label ); ?>
				</strong>
			</div>
			<p class="wp-mcp-adapter-hint">
				<?php echo esc_html( $status['message'] ); ?>
				<?php if ( ! empty( $status['docs_url'] ) ) : ?>
					&mdash;
					<a href="<?php echo esc_url( $status['docs_url'] ); ?>" target="_blank" rel="noreferrer noopener">
						<?php esc_html_e( 'Hosting setup guide', 'mcp-adapter' ); ?>
					</a>
				<?php endif; ?>
			</p>
		</div>
		<?php
	}

	/**
	 * POST handler — revoke a bridge.
	 */
	public static function handle_action(): void {
		$capability = function_exists( 'is_network_admin' ) && is_network_admin() ? 'manage_network_options' : 'manage_options';
		if ( ! current_user_can( $capability ) ) {
			return;
		}

		$action = isset( $_POST[ self::ACTION_FIELD ] ) ? sanitize_key( wp_unslash( (string) $_POST[ self::ACTION_FIELD ] ) ) : '';
		if ( '' === $action ) {
			return;
		}

		$nonce = isset( $_POST[ self::NONCE_FIELD ] ) ? sanitize_text_field( wp_unslash( (string) $_POST[ self::NONCE_FIELD ] ) ) : '';
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, self::NONCE_ACTION ) ) {
			return;
		}

		if ( self::ACTION_REVOKE !== $action ) {
			return;
		}

		$client_id = isset( $_POST['client_id'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['client_id'] ) ) : '';
		if ( '' === $client_id ) {
			return;
		}

		ClientRegistry::revoke( $client_id );

		\oauth_log_boundary( 'boundary.oauth_token_revoked', array(
			'client_id' => $client_id,
			'user_id'   => (int) get_current_user_id(),
			'reason'    => 'admin_revoked',
		) );

		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( AdapterAdminPage::tab_url( AdapterAdminPage::TAB_BRIDGES, array( 'mcp_bridges_flash' => 'revoked' ) ) );
			exit;
		}
	}

	// ─── Helpers ────────────────────────────────────────────────────────────────

	/** Most recent active token row for a client_id. */
	private static function latest_token_for( string $client_id ): ?object {
		global $wpdb;
		if ( ! isset( $wpdb ) ) {
			return null;
		}
		$table = $wpdb->prefix . 'kl_oauth_tokens';
		$row   = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT user_id, scope, last_used_at, expires_at, revoked
				 FROM `{$table}` WHERE client_id = %s AND revoked = 0
				 ORDER BY created_at DESC LIMIT 1",
				$client_id
			)
		);
		return $row ?: null;
	}

	/** Resolve a user login by ID; returns empty string when unknown. */
	private static function user_login( int $user_id ): string {
		if ( $user_id <= 0 || ! function_exists( 'get_userdata' ) ) {
			return '';
		}
		$user = get_userdata( $user_id );
		return $user && isset( $user->user_login ) ? (string) $user->user_login : '';
	}

	/** Format a 'Y-m-d H:i:s' UTC datetime for the operator's local view. */
	private static function format_datetime( ?string $datetime ): string {
		if ( null === $datetime || '' === $datetime ) {
			return '—';
		}
		$timestamp = strtotime( $datetime . ' UTC' );
		if ( ! $timestamp ) {
			return $datetime;
		}
		if ( function_exists( 'wp_date' ) ) {
			$format = function_exists( 'get_option' ) ? get_option( 'date_format', 'Y-m-d' ) . ' ' . get_option( 'time_format', 'H:i' ) : 'Y-m-d H:i';
			return (string) wp_date( $format, $timestamp );
		}
		return gmdate( 'Y-m-d H:i', $timestamp );
	}

	/**
	 * Resolve the diagnostic status from the reserved filter, with a fallback.
	 *
	 * @return array{state:string,message:string,docs_url:string}
	 */
	private static function resolve_status(): array {
		$default = array(
			'state'    => 'unknown',
			'message'  => __( 'Authorization-header detection has not reported yet. The diagnostic activates once a bridge has talked to this site.', 'mcp-adapter' ),
			'docs_url' => '',
		);

		$reported = function_exists( 'apply_filters' ) ? apply_filters( self::DIAGNOSTIC_FILTER, null ) : null;

		if ( ! is_array( $reported ) ) {
			return $default;
		}

		$state = isset( $reported['state'] ) && in_array( $reported['state'], array( 'ok', 'warn', 'unknown' ), true )
			? $reported['state']
			: 'unknown';

		$message = isset( $reported['message'] ) && is_string( $reported['message'] ) && '' !== $reported['message']
			? $reported['message']
			: $default['message'];

		$docs_url = isset( $reported['docs_url'] ) && is_string( $reported['docs_url'] )
			? $reported['docs_url']
			: '';

		return array(
			'state'    => $state,
			'message'  => $message,
			'docs_url' => $docs_url,
		);
	}

	/** Render an inline flash message after a revoke. */
	private static function render_flash( string $flash ): void {
		if ( 'revoked' !== $flash ) {
			return;
		}
		?>
		<div class="notice notice-success">
			<p><?php esc_html_e( 'Bridge revoked. All its tokens have been invalidated.', 'mcp-adapter' ); ?></p>
		</div>
		<?php
	}
}
