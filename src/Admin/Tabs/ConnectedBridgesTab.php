<?php
/**
 * Connected Bridges tab — Phase 2 placeholder shell.
 *
 * The full bridge listing (registered clients, authorized user, scopes, last
 * used, expires, revoke action) is Phase 3 work. This file ships only the
 * empty tab shell so the operator sees the navigation entry, plus the
 * Authorization-header diagnostic hook reserved by the OAuth design doc
 * (Appendix H.2.6 — "Connected Bridges diagnostic tab").
 *
 * Diagnostic data source — extension hook:
 *
 *   apply_filters( 'mcp_adapter_bridges_authorization_header_status', null );
 *
 * Returning shape — null OR an associative array:
 *   [
 *     'state'   => 'ok' | 'warn' | 'unknown', // required
 *     'message' => string,                    // operator-facing line
 *     'docs_url'=> string,                    // optional link target
 *   ]
 *
 * Phase 1's AuthorizationServer is free to implement this filter once the
 * /oauth/echo-headers debug endpoint exists. Until that ships, the tab
 * renders the "unknown" fallback. No Phase 3 functionality is embedded
 * here — just the seam.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Admin\Tabs;

/**
 * Placeholder Connected Bridges tab + reserved diagnostic seam.
 */
final class ConnectedBridgesTab {

	/** Filter hook reserved for the H.2.6 Authorization-header diagnostic. */
	public const DIAGNOSTIC_FILTER = 'mcp_adapter_bridges_authorization_header_status';

	/**
	 * Render the placeholder body.
	 */
	public static function render(): void {
		?>
		<p><?php esc_html_e( 'Bridges that have authorized themselves against this site via OAuth 2.1 will be listed here. The full Connected Bridges UI ships in the next release.', 'mcp-adapter' ); ?></p>

		<div class="wp-mcp-adapter-empty-state">
			<p class="wp-mcp-adapter-empty-state-title"><?php esc_html_e( 'No bridges yet', 'mcp-adapter' ); ?></p>
			<p>
				<?php esc_html_e( 'When an MCP bridge completes the OAuth authorization flow, it will appear here with the user it acts on behalf of, the scopes it requested, and a revoke action.', 'mcp-adapter' ); ?>
			</p>
		</div>

		<?php self::render_authorization_header_diagnostic(); ?>
		<?php
	}

	/**
	 * Render the Authorization-header diagnostic card.
	 *
	 * Per H.2.6 the Connected Bridges tab must reserve a hook for this
	 * diagnostic. The card is shipped now; the data source is delivered
	 * by Phase 3 (or any later phase that hooks the filter).
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
		<h2><?php esc_html_e( 'Authorization header diagnostic', 'mcp-adapter' ); ?></h2>
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
}
