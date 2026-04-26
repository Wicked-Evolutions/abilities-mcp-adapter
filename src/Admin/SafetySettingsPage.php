<?php
/**
 * Safety Settings — admin page.
 *
 * Operator-facing surface for the redaction filter (DB-2) and trusted-proxy
 * configuration (DB-4). Four sections:
 *   1. Master toggle (off requires checkbox confirmation)
 *   2. Redaction keyword list — Bucket 1 read-only, Bucket 2 (warning per remove),
 *      Bucket 3 (no warning), custom add input.
 *   3. Per-ability exemptions — two columns (Bucket 3 left, Bucket 2 right).
 *   4. Trusted proxy (Cloudflare preset / custom CIDR allowlist).
 *
 * All writes log boundary.* events to the kl_boundary log via the adapter's
 * existing BoundaryEventEmitter.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Admin;

use WickedEvolutions\McpAdapter\Infrastructure\Observability\BoundaryEventEmitter;
use WickedEvolutions\McpAdapter\Settings\SafetySettingsRepository as Repo;

/**
 * Safety Settings admin page (Settings → MCP Safety).
 */
final class SafetySettingsPage {

	public const PAGE_SLUG   = 'mcp-adapter-safety';
	private const NONCE_FORM = 'mcp_adapter_safety_save';

	public static function register(): void {
		add_action( 'admin_menu', array( self::class, 'add_menu_page' ) );
		add_action( 'admin_init', array( self::class, 'handle_save' ) );
	}

	public static function add_menu_page(): void {
		add_options_page(
			__( 'MCP Safety Settings', 'mcp-adapter' ),
			__( 'MCP Safety', 'mcp-adapter' ),
			'manage_options',
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function page_url( array $args = array() ): string {
		$args['page'] = self::PAGE_SLUG;
		return add_query_arg( $args, admin_url( 'options-general.php' ) );
	}

	/**
	 * Process the settings form. The form has multiple "actions" multiplexed
	 * onto a single endpoint via the `mcp_safety_action` hidden field.
	 */
	public static function handle_save(): void {
		if ( ! isset( $_POST['mcp_safety_action'] ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to manage safety settings.', 'mcp-adapter' ) );
		}
		check_admin_referer( self::NONCE_FORM, 'mcp_safety_nonce' );

		$action = sanitize_key( wp_unslash( $_POST['mcp_safety_action'] ) );
		$notice = '';

		switch ( $action ) {
			case 'master_toggle':
				$notice = self::handle_master_toggle();
				break;
			case 'add_keyword':
				$notice = self::handle_add_keyword();
				break;
			case 'remove_custom_keyword':
				$notice = self::handle_remove_custom_keyword();
				break;
			case 'remove_default_keyword':
				$notice = self::handle_remove_default_keyword();
				break;
			case 'restore_defaults':
				$notice = self::handle_restore_defaults();
				break;
			case 'set_exemption':
				$notice = self::handle_set_exemption();
				break;
			case 'unset_exemption':
				$notice = self::handle_unset_exemption();
				break;
			case 'trusted_proxy':
				$notice = self::handle_trusted_proxy();
				break;
		}

		wp_safe_redirect( self::page_url( array( 'updated' => '1', 'msg' => rawurlencode( $notice ) ) ) );
		exit;
	}

	private static function handle_master_toggle(): string {
		$desired = isset( $_POST['mcp_master_enabled'] ) ? '1' === $_POST['mcp_master_enabled'] : true;
		$confirmed = isset( $_POST['mcp_master_confirm'] ) && '1' === $_POST['mcp_master_confirm'];

		$current = Repo::is_master_enabled();
		if ( $desired === $current ) {
			return __( 'No change to master toggle.', 'mcp-adapter' );
		}

		// Disabling requires the inner checkbox.
		if ( ! $desired && ! $confirmed ) {
			return __( 'Disabling personal-data filtering requires confirming the warning checkbox.', 'mcp-adapter' );
		}

		Repo::set_master_enabled( $desired );

		BoundaryEventEmitter::emit(
			self::observability_handler(),
			'boundary.master_toggle.changed',
			array(
				'severity' => $desired ? 'info' : 'warn',
				'user_id'  => (int) get_current_user_id(),
				'reason'   => $desired ? 'enabled' : 'disabled',
			)
		);

		return $desired
			? __( 'Personal-data filtering enabled.', 'mcp-adapter' )
			: __( 'Personal-data filtering disabled. Bucket 1 secrets remain redacted regardless.', 'mcp-adapter' );
	}

	private static function handle_add_keyword(): string {
		$keyword = isset( $_POST['mcp_keyword'] ) ? (string) wp_unslash( $_POST['mcp_keyword'] ) : '';
		$bucket  = isset( $_POST['mcp_bucket'] ) ? (int) $_POST['mcp_bucket'] : 0;

		if ( Repo::BUCKET_PAYMENT !== $bucket && Repo::BUCKET_CONTACT !== $bucket ) {
			return __( 'Bucket must be 2 or 3.', 'mcp-adapter' );
		}

		$result = Repo::add_custom_keyword( $bucket, $keyword );
		if ( is_wp_error( $result ) ) {
			return $result->get_error_message();
		}

		BoundaryEventEmitter::emit(
			self::observability_handler(),
			'boundary.redaction_keywords.changed',
			array(
				'severity' => 'info',
				'user_id'  => (int) get_current_user_id(),
				'reason'   => 'add_custom',
				'name'     => sanitize_key( $keyword ),
				'dimension' => 'bucket_' . $bucket,
			)
		);

		return $result
			? __( 'Keyword added.', 'mcp-adapter' )
			: __( 'Keyword already present.', 'mcp-adapter' );
	}

	private static function handle_remove_custom_keyword(): string {
		$keyword = isset( $_POST['mcp_keyword'] ) ? (string) wp_unslash( $_POST['mcp_keyword'] ) : '';
		$bucket  = isset( $_POST['mcp_bucket'] ) ? (int) $_POST['mcp_bucket'] : 0;

		$result = Repo::remove_custom_keyword( $bucket, $keyword );
		if ( is_wp_error( $result ) ) {
			return $result->get_error_message();
		}

		BoundaryEventEmitter::emit(
			self::observability_handler(),
			'boundary.redaction_keywords.changed',
			array(
				'severity' => 'info',
				'user_id'  => (int) get_current_user_id(),
				'reason'   => 'remove_custom',
				'name'     => sanitize_key( $keyword ),
				'dimension' => 'bucket_' . $bucket,
			)
		);

		return $result
			? __( 'Custom keyword removed.', 'mcp-adapter' )
			: __( 'Keyword was not in the custom list.', 'mcp-adapter' );
	}

	private static function handle_remove_default_keyword(): string {
		$keyword   = isset( $_POST['mcp_keyword'] ) ? (string) wp_unslash( $_POST['mcp_keyword'] ) : '';
		$bucket    = isset( $_POST['mcp_bucket'] ) ? (int) $_POST['mcp_bucket'] : 0;
		$confirmed = isset( $_POST['mcp_default_confirm'] ) && '1' === $_POST['mcp_default_confirm'];

		// Bucket 2 default removal requires the in-form checkbox confirmation.
		if ( Repo::BUCKET_PAYMENT === $bucket && ! $confirmed ) {
			return __( 'Removing a Bucket 2 default keyword requires confirming the warning checkbox.', 'mcp-adapter' );
		}

		$result = Repo::remove_default_keyword( $bucket, $keyword );
		if ( is_wp_error( $result ) ) {
			return $result->get_error_message();
		}

		BoundaryEventEmitter::emit(
			self::observability_handler(),
			'boundary.redaction_keywords.changed',
			array(
				'severity' => Repo::BUCKET_PAYMENT === $bucket ? 'warn' : 'info',
				'user_id'  => (int) get_current_user_id(),
				'reason'   => 'remove_default',
				'name'     => sanitize_key( $keyword ),
				'dimension' => 'bucket_' . $bucket,
			)
		);

		return $result
			? __( 'Default keyword removed. Restore defaults to bring it back.', 'mcp-adapter' )
			: __( 'Keyword was already removed.', 'mcp-adapter' );
	}

	private static function handle_restore_defaults(): string {
		Repo::restore_defaults();

		BoundaryEventEmitter::emit(
			self::observability_handler(),
			'boundary.redaction_keywords.changed',
			array(
				'severity' => 'info',
				'user_id'  => (int) get_current_user_id(),
				'reason'   => 'restore_defaults',
			)
		);

		return __( 'Redaction lists restored to defaults.', 'mcp-adapter' );
	}

	private static function handle_set_exemption(): string {
		$ability   = isset( $_POST['mcp_ability'] ) ? (string) wp_unslash( $_POST['mcp_ability'] ) : '';
		$bucket    = isset( $_POST['mcp_bucket'] ) ? (int) $_POST['mcp_bucket'] : 0;
		$confirmed = isset( $_POST['mcp_exempt_confirm'] ) && '1' === $_POST['mcp_exempt_confirm'];

		if ( Repo::BUCKET_PAYMENT === $bucket && ! $confirmed ) {
			return __( 'Exempting an ability from Bucket 2 requires confirming the warning checkbox.', 'mcp-adapter' );
		}

		$result = Repo::add_exemption( $bucket, $ability );
		if ( is_wp_error( $result ) ) {
			return $result->get_error_message();
		}

		BoundaryEventEmitter::emit(
			self::observability_handler(),
			'boundary.ability_exemption.changed',
			array(
				'severity' => Repo::BUCKET_PAYMENT === $bucket ? 'warn' : 'info',
				'user_id'  => (int) get_current_user_id(),
				'reason'   => 'add',
				'name'     => sanitize_text_field( $ability ),
				'dimension' => 'bucket_' . $bucket,
			)
		);

		return $result
			? __( 'Exemption added.', 'mcp-adapter' )
			: __( 'Ability was already exempt.', 'mcp-adapter' );
	}

	private static function handle_unset_exemption(): string {
		$ability = isset( $_POST['mcp_ability'] ) ? (string) wp_unslash( $_POST['mcp_ability'] ) : '';
		$bucket  = isset( $_POST['mcp_bucket'] ) ? (int) $_POST['mcp_bucket'] : 0;

		$result = Repo::remove_exemption( $bucket, $ability );
		if ( is_wp_error( $result ) ) {
			return $result->get_error_message();
		}

		BoundaryEventEmitter::emit(
			self::observability_handler(),
			'boundary.ability_exemption.changed',
			array(
				'severity' => 'info',
				'user_id'  => (int) get_current_user_id(),
				'reason'   => 'remove',
				'name'     => sanitize_text_field( $ability ),
				'dimension' => 'bucket_' . $bucket,
			)
		);

		return $result
			? __( 'Exemption removed.', 'mcp-adapter' )
			: __( 'Ability was not exempt.', 'mcp-adapter' );
	}

	private static function handle_trusted_proxy(): string {
		$enabled   = isset( $_POST['mcp_proxy_enabled'] ) && '1' === $_POST['mcp_proxy_enabled'];
		$mode      = isset( $_POST['mcp_proxy_mode'] ) ? sanitize_key( wp_unslash( $_POST['mcp_proxy_mode'] ) ) : Repo::PROXY_MODE_CLOUDFLARE;
		$allowlist = isset( $_POST['mcp_proxy_allowlist'] ) ? (string) wp_unslash( $_POST['mcp_proxy_allowlist'] ) : '';
		// Sanitize allowlist: keep one CIDR/IP per line, strip blanks/comments.
		$lines = preg_split( "/\r?\n/", $allowlist ) ?: array();
		$clean = array();
		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( '' === $line || str_starts_with( $line, '#' ) ) {
				continue;
			}
			$line = preg_replace( '/[^0-9a-fA-F:.\\/]/', '', $line ) ?? '';
			if ( '' !== $line ) {
				$clean[] = $line;
			}
		}
		$allowlist = implode( "\n", $clean );

		Repo::set_trusted_proxy_enabled( $enabled );
		Repo::set_trusted_proxy_mode( $mode );
		Repo::set_trusted_proxy_allowlist_raw( $allowlist );

		return __( 'Trusted proxy settings saved.', 'mcp-adapter' );
	}

	/**
	 * Render the settings page.
	 */
	public static function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'MCP Safety Settings', 'mcp-adapter' ); ?></h1>
			<p><?php esc_html_e( 'Controls the redaction filter that runs at the /mcp response boundary, plus trusted-proxy IP detection used by the rate limiter.', 'mcp-adapter' ); ?></p>

			<?php if ( isset( $_GET['updated'] ) && '1' === $_GET['updated'] ) : ?>
				<div class="notice notice-success is-dismissible">
					<p><?php echo esc_html( isset( $_GET['msg'] ) ? rawurldecode( wp_unslash( (string) $_GET['msg'] ) ) : __( 'Settings saved.', 'mcp-adapter' ) ); ?></p>
				</div>
			<?php endif; ?>

			<?php
			self::render_master_toggle_section();
			self::render_keyword_list_section();
			self::render_exemptions_section();
			self::render_trusted_proxy_section();
			?>
		</div>
		<?php
	}

	private static function render_master_toggle_section(): void {
		$enabled = Repo::is_master_enabled();
		?>
		<h2><?php esc_html_e( '1. Master Toggle', 'mcp-adapter' ); ?></h2>
		<form method="post" action="" style="background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:16px;max-width:780px;">
			<?php wp_nonce_field( self::NONCE_FORM, 'mcp_safety_nonce' ); ?>
			<input type="hidden" name="mcp_safety_action" value="master_toggle" />

			<label style="display:flex;align-items:flex-start;gap:8px;">
				<input type="checkbox" name="mcp_master_enabled" value="1" <?php checked( $enabled ); ?> id="mcp-master-toggle" />
				<span>
					<strong><?php esc_html_e( 'Filter personal data and payment identifiers in AI responses', 'mcp-adapter' ); ?></strong><br>
					<span style="color:#646970;font-size:13px;"><?php esc_html_e( 'Default ON. Bucket 1 secrets (passwords, API keys, tokens) are filtered regardless.', 'mcp-adapter' ); ?></span>
				</span>
			</label>

			<div id="mcp-master-warning" style="margin-top:12px;<?php echo $enabled ? '' : 'display:none;'; ?>padding:12px;background:#fcf0f1;border-left:4px solid #d63638;">
				<p style="margin:0 0 8px;font-weight:600;color:#d63638;">⚠️ <?php esc_html_e( 'Disabling personal-data and payment-identifier filtering', 'mcp-adapter' ); ?></p>
				<p style="margin:0 0 8px;font-size:13px;">
					<?php esc_html_e( 'When this is off, AI clients connected to your site will receive the full contents of every ability response — including email addresses, phone numbers, postal addresses, IP addresses, payment-related identifiers, and other personal data attached to your users and customers.', 'mcp-adapter' ); ?>
				</p>
				<p style="margin:0 0 8px;font-size:13px;">
					<em><?php esc_html_e( 'Note: Authentication credentials, password hashes, API keys, and session tokens remain filtered regardless of this setting.', 'mcp-adapter' ); ?></em>
				</p>
				<p style="margin:0 0 8px;font-size:13px;">
					<?php esc_html_e( 'If you handle personal data, payment data, or operate in a regulated industry, disabling personal-data filtering may put you out of compliance with GDPR, PCI-DSS, HIPAA, or similar laws.', 'mcp-adapter' ); ?>
				</p>
				<label style="display:flex;align-items:center;gap:6px;font-size:13px;">
					<input type="checkbox" name="mcp_master_confirm" value="1" />
					<?php esc_html_e( 'I understand and accept the risk. Disable personal-data filtering.', 'mcp-adapter' ); ?>
				</label>
			</div>

			<p style="margin-top:12px;">
				<?php submit_button( __( 'Save Master Toggle', 'mcp-adapter' ), 'primary', 'submit', false ); ?>
			</p>
		</form>
		<script>
		(function(){
			var t = document.getElementById('mcp-master-toggle');
			var w = document.getElementById('mcp-master-warning');
			if (!t || !w) return;
			function sync(){ w.style.display = t.checked ? 'none' : 'block'; }
			t.addEventListener('change', sync);
			sync();
		})();
		</script>
		<?php
	}

	private static function render_keyword_list_section(): void {
		?>
		<h2><?php esc_html_e( '2. Redaction Keyword List', 'mcp-adapter' ); ?></h2>

		<h3><?php esc_html_e( 'Bucket 1 — Secrets (always-on)', 'mcp-adapter' ); ?></h3>
		<p style="color:#646970;"><?php esc_html_e( 'These secrets are always filtered. They cannot be disabled.', 'mcp-adapter' ); ?></p>
		<div style="background:#f6f7f7;border:1px solid #dcdcde;border-radius:4px;padding:12px;max-width:780px;font-family:monospace;font-size:12px;line-height:1.6;">
			<?php echo esc_html( implode( ', ', Repo::bucket1_default_keywords() ) ); ?>
		</div>

		<h3 style="margin-top:24px;"><?php esc_html_e( 'Bucket 2 — Payment / Regulated Identifiers', 'mcp-adapter' ); ?></h3>
		<p style="color:#646970;"><?php esc_html_e( 'Configurable via this admin UI ONLY. Cannot be weakened by AI.', 'mcp-adapter' ); ?></p>
		<?php self::render_bucket_table( Repo::BUCKET_PAYMENT ); ?>

		<h3 style="margin-top:24px;"><?php esc_html_e( 'Bucket 3 — Contact PII / Access Labels', 'mcp-adapter' ); ?></h3>
		<p style="color:#646970;"><?php esc_html_e( 'Configurable via admin UI or AI ability. Default keyword removal does not require an extra warning here (matches the AI confirmation friction).', 'mcp-adapter' ); ?></p>
		<?php self::render_bucket_table( Repo::BUCKET_CONTACT ); ?>

		<h3 style="margin-top:24px;"><?php esc_html_e( 'Add a custom keyword', 'mcp-adapter' ); ?></h3>
		<form method="post" action="" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;max-width:780px;">
			<?php wp_nonce_field( self::NONCE_FORM, 'mcp_safety_nonce' ); ?>
			<input type="hidden" name="mcp_safety_action" value="add_keyword" />
			<input type="text" name="mcp_keyword" placeholder="e.g. gravity_forms_secret" required
				style="flex:1;min-width:240px;padding:6px 8px;font-family:monospace;" />
			<select name="mcp_bucket">
				<option value="3"><?php esc_html_e( 'Bucket 3 (contact PII)', 'mcp-adapter' ); ?></option>
				<option value="2"><?php esc_html_e( 'Bucket 2 (payment / regulated)', 'mcp-adapter' ); ?></option>
			</select>
			<?php submit_button( __( 'Add', 'mcp-adapter' ), 'secondary', 'submit', false ); ?>
		</form>
		<p style="color:#646970;font-size:12px;margin-top:6px;">
			<?php esc_html_e( 'Bucket 1 is hardcoded. Custom keywords go to Bucket 2 or Bucket 3 only.', 'mcp-adapter' ); ?>
		</p>

		<form method="post" action="" style="margin-top:16px;">
			<?php wp_nonce_field( self::NONCE_FORM, 'mcp_safety_nonce' ); ?>
			<input type="hidden" name="mcp_safety_action" value="restore_defaults" />
			<?php submit_button( __( 'Restore default redaction lists', 'mcp-adapter' ), 'secondary', 'submit', false, array( 'onclick' => "return confirm('Restore both Bucket 2 and Bucket 3 to factory defaults? Custom additions and removed defaults will be cleared.')" ) ); ?>
		</form>
		<?php
	}

	private static function render_bucket_table( int $bucket ): void {
		$active   = Repo::get_active_keywords( $bucket );
		$customs  = array_flip( Repo::get_custom_keywords( $bucket ) );
		$defaults = Repo::BUCKET_PAYMENT === $bucket
			? Repo::bucket2_default_keywords()
			: Repo::bucket3_default_keywords();
		$default_set = array_flip( array_map( 'strtolower', $defaults ) );

		// Build merged list: active + recently-removed defaults so the operator can see both states.
		$removed_defaults = Repo::get_removed_defaults( $bucket );

		?>
		<table class="widefat striped" style="max-width:780px;">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Keyword', 'mcp-adapter' ); ?></th>
					<th style="width:120px;"><?php esc_html_e( 'Source', 'mcp-adapter' ); ?></th>
					<th style="width:200px;"><?php esc_html_e( 'Action', 'mcp-adapter' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $active as $kw ) : ?>
					<tr>
						<td><code><?php echo esc_html( $kw ); ?></code></td>
						<td>
							<?php
							if ( isset( $customs[ $kw ] ) ) {
								esc_html_e( 'Custom', 'mcp-adapter' );
							} elseif ( isset( $default_set[ $kw ] ) ) {
								esc_html_e( 'Default', 'mcp-adapter' );
							} else {
								esc_html_e( 'Active', 'mcp-adapter' );
							}
							?>
						</td>
						<td>
							<?php if ( isset( $customs[ $kw ] ) ) : ?>
								<form method="post" action="" style="margin:0;">
									<?php wp_nonce_field( self::NONCE_FORM, 'mcp_safety_nonce' ); ?>
									<input type="hidden" name="mcp_safety_action" value="remove_custom_keyword" />
									<input type="hidden" name="mcp_keyword" value="<?php echo esc_attr( $kw ); ?>" />
									<input type="hidden" name="mcp_bucket" value="<?php echo esc_attr( (string) $bucket ); ?>" />
									<button type="submit" class="button-link-delete"><?php esc_html_e( 'Remove (custom)', 'mcp-adapter' ); ?></button>
								</form>
							<?php elseif ( isset( $default_set[ $kw ] ) ) : ?>
								<?php if ( Repo::BUCKET_PAYMENT === $bucket ) : ?>
									<form method="post" action="" style="margin:0;" onsubmit="return confirm('Remove default Bucket 2 keyword \'<?php echo esc_js( $kw ); ?>\'? This exposes payment / regulated identifiers in matching field names.')">
										<?php wp_nonce_field( self::NONCE_FORM, 'mcp_safety_nonce' ); ?>
										<input type="hidden" name="mcp_safety_action" value="remove_default_keyword" />
										<input type="hidden" name="mcp_keyword" value="<?php echo esc_attr( $kw ); ?>" />
										<input type="hidden" name="mcp_bucket" value="<?php echo esc_attr( (string) $bucket ); ?>" />
										<input type="hidden" name="mcp_default_confirm" value="1" />
										<button type="submit" class="button-link-delete">
											⚠️ <?php esc_html_e( 'Remove default (warning)', 'mcp-adapter' ); ?>
										</button>
									</form>
								<?php else : ?>
									<form method="post" action="" style="margin:0;">
										<?php wp_nonce_field( self::NONCE_FORM, 'mcp_safety_nonce' ); ?>
										<input type="hidden" name="mcp_safety_action" value="remove_default_keyword" />
										<input type="hidden" name="mcp_keyword" value="<?php echo esc_attr( $kw ); ?>" />
										<input type="hidden" name="mcp_bucket" value="<?php echo esc_attr( (string) $bucket ); ?>" />
										<button type="submit" class="button-link-delete"><?php esc_html_e( 'Remove default', 'mcp-adapter' ); ?></button>
									</form>
								<?php endif; ?>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				<?php foreach ( $removed_defaults as $kw ) : ?>
					<tr style="opacity:0.55;">
						<td><code style="text-decoration:line-through;"><?php echo esc_html( $kw ); ?></code></td>
						<td><em><?php esc_html_e( 'Default removed', 'mcp-adapter' ); ?></em></td>
						<td>
							<form method="post" action="" style="margin:0;">
								<?php wp_nonce_field( self::NONCE_FORM, 'mcp_safety_nonce' ); ?>
								<input type="hidden" name="mcp_safety_action" value="add_keyword" />
								<input type="hidden" name="mcp_keyword" value="<?php echo esc_attr( $kw ); ?>" />
								<input type="hidden" name="mcp_bucket" value="<?php echo esc_attr( (string) $bucket ); ?>" />
								<button type="submit" class="button"><?php esc_html_e( 'Restore', 'mcp-adapter' ); ?></button>
							</form>
						</td>
					</tr>
				<?php endforeach; ?>
				<?php if ( empty( $active ) && empty( $removed_defaults ) ) : ?>
					<tr><td colspan="3"><em><?php esc_html_e( 'No keywords configured.', 'mcp-adapter' ); ?></em></td></tr>
				<?php endif; ?>
			</tbody>
		</table>
		<?php
	}

	private static function render_exemptions_section(): void {
		$abilities  = self::list_public_abilities();
		$exempt_b3  = array_flip( Repo::get_exemptions( Repo::BUCKET_CONTACT ) );
		$exempt_b2  = array_flip( Repo::get_exemptions( Repo::BUCKET_PAYMENT ) );
		?>
		<h2><?php esc_html_e( '3. Per-Ability Exemptions', 'mcp-adapter' ); ?></h2>
		<p><?php esc_html_e( 'Exempt specific abilities from redaction. Bucket 2 exemptions can only be granted from this admin UI.', 'mcp-adapter' ); ?></p>

		<div style="display:flex;gap:24px;flex-wrap:wrap;max-width:1200px;">
			<div style="flex:1;min-width:380px;">
				<h3><?php esc_html_e( 'Exempt from Bucket 3 (contact PII)', 'mcp-adapter' ); ?></h3>
				<table class="widefat striped">
					<thead>
						<tr>
							<th style="width:60px;"><?php esc_html_e( 'Exempt', 'mcp-adapter' ); ?></th>
							<th><?php esc_html_e( 'Ability', 'mcp-adapter' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $abilities as $name ) : ?>
							<?php $is_exempt = isset( $exempt_b3[ $name ] ); ?>
							<tr>
								<td>
									<form method="post" action="" style="margin:0;">
										<?php wp_nonce_field( self::NONCE_FORM, 'mcp_safety_nonce' ); ?>
										<input type="hidden" name="mcp_safety_action" value="<?php echo $is_exempt ? 'unset_exemption' : 'set_exemption'; ?>" />
										<input type="hidden" name="mcp_ability" value="<?php echo esc_attr( $name ); ?>" />
										<input type="hidden" name="mcp_bucket" value="3" />
										<button type="submit" class="button" style="padding:1px 8px;">
											<?php echo $is_exempt ? esc_html__( 'Yes ✓', 'mcp-adapter' ) : esc_html__( 'No', 'mcp-adapter' ); ?>
										</button>
									</form>
								</td>
								<td><code><?php echo esc_html( $name ); ?></code></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>

			<div style="flex:1;min-width:380px;">
				<h3><?php esc_html_e( 'Exempt from Bucket 2 (payment / regulated)', 'mcp-adapter' ); ?></h3>
				<table class="widefat striped">
					<thead>
						<tr>
							<th style="width:60px;"><?php esc_html_e( 'Exempt', 'mcp-adapter' ); ?></th>
							<th><?php esc_html_e( 'Ability', 'mcp-adapter' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $abilities as $name ) : ?>
							<?php $is_exempt = isset( $exempt_b2[ $name ] ); ?>
							<tr>
								<td>
									<?php if ( $is_exempt ) : ?>
										<form method="post" action="" style="margin:0;">
											<?php wp_nonce_field( self::NONCE_FORM, 'mcp_safety_nonce' ); ?>
											<input type="hidden" name="mcp_safety_action" value="unset_exemption" />
											<input type="hidden" name="mcp_ability" value="<?php echo esc_attr( $name ); ?>" />
											<input type="hidden" name="mcp_bucket" value="2" />
											<button type="submit" class="button" style="padding:1px 8px;"><?php esc_html_e( 'Yes ✓', 'mcp-adapter' ); ?></button>
										</form>
									<?php else : ?>
										<form method="post" action="" style="margin:0;"
											onsubmit="return confirm('Are you sure? Exempting <?php echo esc_js( $name ); ?> from Bucket 2 will expose card_number, ssn, etc. for this specific ability.')">
											<?php wp_nonce_field( self::NONCE_FORM, 'mcp_safety_nonce' ); ?>
											<input type="hidden" name="mcp_safety_action" value="set_exemption" />
											<input type="hidden" name="mcp_ability" value="<?php echo esc_attr( $name ); ?>" />
											<input type="hidden" name="mcp_bucket" value="2" />
											<input type="hidden" name="mcp_exempt_confirm" value="1" />
											<button type="submit" class="button" style="padding:1px 8px;">⚠️ <?php esc_html_e( 'No', 'mcp-adapter' ); ?></button>
										</form>
									<?php endif; ?>
								</td>
								<td><code><?php echo esc_html( $name ); ?></code></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private static function render_trusted_proxy_section(): void {
		$enabled   = Repo::is_trusted_proxy_enabled();
		$mode      = Repo::get_trusted_proxy_mode();
		$allowlist = Repo::get_trusted_proxy_allowlist_raw();
		?>
		<h2><?php esc_html_e( '4. Trusted Proxy', 'mcp-adapter' ); ?></h2>
		<p><?php esc_html_e( 'Configure how the rate limiter detects the real client IP when your site is behind a CDN or load balancer.', 'mcp-adapter' ); ?></p>

		<form method="post" action="" style="background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:16px;max-width:780px;">
			<?php wp_nonce_field( self::NONCE_FORM, 'mcp_safety_nonce' ); ?>
			<input type="hidden" name="mcp_safety_action" value="trusted_proxy" />

			<label style="display:flex;align-items:center;gap:8px;">
				<input type="checkbox" name="mcp_proxy_enabled" value="1" <?php checked( $enabled ); ?> />
				<strong><?php esc_html_e( 'Enable trusted proxy IP detection', 'mcp-adapter' ); ?></strong>
			</label>

			<fieldset style="margin-top:16px;border:1px solid #dcdcde;border-radius:4px;padding:12px;">
				<legend style="padding:0 6px;font-weight:600;"><?php esc_html_e( 'Mode', 'mcp-adapter' ); ?></legend>

				<label style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
					<input type="radio" name="mcp_proxy_mode" value="cloudflare" <?php checked( $mode, Repo::PROXY_MODE_CLOUDFLARE ); ?> />
					<span>
						<strong><?php esc_html_e( 'Cloudflare preset', 'mcp-adapter' ); ?></strong><br>
						<span style="color:#646970;font-size:13px;">
							<?php esc_html_e( 'Adapter accepts CF-Connecting-IP only when REMOTE_ADDR is a Cloudflare edge IP.', 'mcp-adapter' ); ?>
						</span>
					</span>
				</label>

				<label style="display:flex;align-items:flex-start;gap:8px;">
					<input type="radio" name="mcp_proxy_mode" value="custom" <?php checked( $mode, Repo::PROXY_MODE_CUSTOM ); ?> />
					<span style="flex:1;">
						<strong><?php esc_html_e( 'Custom IP allowlist', 'mcp-adapter' ); ?></strong><br>
						<span style="color:#646970;font-size:13px;"><?php esc_html_e( 'One IP or CIDR range per line. Lines starting with # are ignored.', 'mcp-adapter' ); ?></span><br>
						<textarea name="mcp_proxy_allowlist" rows="4" style="width:100%;font-family:monospace;font-size:12px;margin-top:6px;"
							placeholder="10.0.0.0/8&#10;192.168.1.1"><?php echo esc_textarea( $allowlist ); ?></textarea>
					</span>
				</label>
			</fieldset>

			<p style="margin-top:12px;font-size:12px;color:#646970;">
				<?php esc_html_e( 'Why this matters: when the rate limiter cannot trust X-Forwarded-For, attackers behind the CDN can spoof the client IP and bypass rate limits. The allowlist ensures only requests originating from your CDN edge are trusted.', 'mcp-adapter' ); ?>
			</p>

			<?php submit_button( __( 'Save Trusted Proxy Settings', 'mcp-adapter' ) ); ?>
		</form>
		<?php
	}

	/**
	 * MCP-public ability names, sorted, namespaced.
	 *
	 * @return string[]
	 */
	private static function list_public_abilities(): array {
		if ( ! function_exists( 'wp_get_abilities' ) ) {
			return array();
		}
		$abilities = wp_get_abilities();
		$names     = array();
		foreach ( $abilities as $ability ) {
			if ( ! self::is_mcp_public( $ability ) ) {
				continue;
			}
			$names[] = $ability->get_name();
		}
		sort( $names );
		return $names;
	}

	private static function is_mcp_public( \WP_Ability $ability ): bool {
		if ( method_exists( $ability, 'get_show_in_rest' ) ) {
			$show = $ability->get_show_in_rest();
			if ( null !== $show ) {
				return (bool) $show;
			}
		}
		$meta = $ability->get_meta();
		if ( isset( $meta['show_in_rest'] ) ) {
			return (bool) $meta['show_in_rest'];
		}
		return (bool) ( $meta['mcp']['public'] ?? false );
	}

	/**
	 * Best-effort observability handler from the live adapter, or null.
	 *
	 * Settings writes happen in admin context where the MCP request loop
	 * isn't running, so the typed handler may not be wired. The action
	 * hook (Path 2) still fires regardless — that is the path DB-1's
	 * BoundaryEventLogger uses anyway.
	 */
	private static function observability_handler(): ?\WickedEvolutions\McpAdapter\Infrastructure\Observability\Contracts\McpObservabilityHandlerInterface {
		return null;
	}
}
