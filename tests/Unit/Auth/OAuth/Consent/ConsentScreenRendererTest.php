<?php
/**
 * Tests for ConsentScreenRenderer::build_html() and ::build_error_html().
 *
 * Verifies the rendered HTML contains all the operator-facing pieces the
 * binding spec requires:
 *   - Hidden inputs that round-trip the OAuth flow params (state, code_challenge, etc.)
 *   - Server-issued nonce field (Appendix H.4.5)
 *   - Each requested scope rendered as a TOGGLEABLE checkbox (H.3.4 — none locked)
 *   - "Granted YYYY-MM-DD" badge for previously-granted scopes (H.3.4)
 *   - Sensitive scope badge + lock icon for sensitive scopes (H.3.4)
 *   - Role switcher constrained to provided role list (H.4.5)
 *   - No <script> tags anywhere (server-rendered, no JS — H.4.5)
 *   - All dynamic values escaped (no XSS surface)
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth\Consent;

use PHPUnit\Framework\TestCase;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\ConsentDecision;
use WickedEvolutions\McpAdapter\Auth\OAuth\Consent\ConsentScreenRenderer;

final class ConsentScreenRendererTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wp_test_transients'] = array();
	}

	/** Build a baseline params array a test can mutate. */
	private function params( array $overrides = array() ): array {
		$decision = $overrides['decision'] ?? new ConsentDecision(
			ConsentDecision::RENDER_FULL,
			array( 'abilities:content:read', 'abilities:settings:read' ),
			array( 'abilities:content:read' ),
			array( 'abilities:settings:read' ),
			array( 'abilities:settings:read' ),
			'sensitive_scope_requested'
		);
		return array_merge( array(
			'client_id'                  => 'client-uuid',
			'client_name'                => 'Acme Bridge',
			'redirect_uri'               => 'http://127.0.0.1:8765/cb',
			'scope'                      => 'abilities:content:read abilities:settings:read',
			'state'                      => 'rnd-state-xyz',
			'code_challenge'             => 'CHALLENGE-XXXXXXXXXXXXXXXXXXXXXXXXXX',
			'resource'                   => 'https://example.com/wp-json/mcp/mcp-adapter-default-server',
			'user_id'                    => 7,
			'user_login'                 => 'jacob',
			'user_display'               => 'Jacob Willow',
			'available_roles'            => array( 'editor', 'author' ),
			'decision'                   => $decision,
			'previously_granted_at_unix' => 1_700_000_000,
			'action_url'                 => 'https://example.com/oauth/authorize',
		), $overrides );
	}

	// ─── Form structure ─────────────────────────────────────────────────────────

	public function test_html_contains_form_with_action_url(): void {
		$html = ConsentScreenRenderer::build_html( $this->params() );
		$this->assertStringContainsString( '<form method="post"', $html );
		$this->assertStringContainsString( 'action="https://example.com/oauth/authorize"', $html );
	}

	public function test_html_round_trips_oauth_flow_parameters_as_hidden_inputs(): void {
		$html = $this->collapse_ws( ConsentScreenRenderer::build_html( $this->params() ) );

		$this->assertStringContainsString( 'name="client_id" value="client-uuid"', $html );
		$this->assertStringContainsString( 'name="redirect_uri" value="http://127.0.0.1:8765/cb"', $html );
		$this->assertStringContainsString( 'name="state" value="rnd-state-xyz"', $html );
		$this->assertStringContainsString( 'name="code_challenge" value="CHALLENGE-XXXXXXXXXXXXXXXXXXXXXXXXXX"', $html );
		$this->assertStringContainsString( 'name="code_challenge_method" value="S256"', $html );
		$this->assertStringContainsString( 'name="response_type" value="code"', $html );
	}

	public function test_html_contains_server_issued_scope_nonce(): void {
		$html = ConsentScreenRenderer::build_html( $this->params() );
		$this->assertStringContainsString( 'name="' . ConsentScreenRenderer::NONCE_FIELD . '"', $html );
		$this->assertMatchesRegularExpression(
			'/name="' . ConsentScreenRenderer::NONCE_FIELD . '" value="[a-f0-9]{32}"/',
			$html,
			'Nonce hidden input must contain a 32-hex-char server-issued nonce.'
		);
	}

	// ─── Scope rendering (Appendix H.3.4) ───────────────────────────────────────

	public function test_every_requested_scope_renders_as_toggleable_checkbox(): void {
		$html = $this->collapse_ws( ConsentScreenRenderer::build_html( $this->params() ) );
		$this->assertStringContainsString( 'name="' . ConsentScreenRenderer::SCOPE_FIELD . '[]" value="abilities:content:read" checked', $html );
		$this->assertStringContainsString( 'name="' . ConsentScreenRenderer::SCOPE_FIELD . '[]" value="abilities:settings:read" checked', $html );

		// H.3.4 explicitly requires NO locked rows — `disabled` must not appear on scope inputs.
		$this->assertStringNotContainsString( 'disabled', $html, 'No scope checkbox may be disabled (H.3.4).' );
	}

	public function test_previously_granted_scope_shows_granted_date_badge(): void {
		$html = ConsentScreenRenderer::build_html( $this->params() );
		// timestamp 1_700_000_000 = 2023-11-14 in UTC — that's the badge text.
		$this->assertStringContainsString( 'Granted 2023-11-14', $html );
	}

	public function test_sensitive_scope_shows_sensitive_badge_and_lock_icon(): void {
		$html = ConsentScreenRenderer::build_html( $this->params() );
		$this->assertStringContainsString( 'wp-mcp-consent-badge--sensitive', $html );
		$this->assertStringContainsString( 'wp-mcp-consent-lock', $html );
		$this->assertStringContainsString( 'wp-mcp-consent-group--sensitive', $html );
	}

	// ─── Role switcher (Appendix H.4.5) ─────────────────────────────────────────

	public function test_role_select_lists_only_provided_roles(): void {
		$html = ConsentScreenRenderer::build_html( $this->params() );
		$this->assertStringContainsString( '<option value="editor">editor</option>', $html );
		$this->assertStringContainsString( '<option value="author">author</option>', $html );
		$this->assertStringNotContainsString( 'administrator', $html, 'Role switcher must not list roles outside the provided allowlist.' );
	}

	public function test_role_with_one_option_renders_as_hidden_input_not_select(): void {
		$html = ConsentScreenRenderer::build_html( $this->params( array( 'available_roles' => array( 'subscriber' ) ) ) );
		$this->assertStringContainsString( 'name="' . ConsentScreenRenderer::ROLE_FIELD . '" value="subscriber"', $html );
		$this->assertStringNotContainsString( '<select', $html, 'Single-role users get a hidden input, not a select.' );
	}

	// ─── No JavaScript on the consent screen (Appendix H.4.5) ───────────────────

	public function test_no_script_tags_in_consent_screen(): void {
		$html = ConsentScreenRenderer::build_html( $this->params() );
		$this->assertStringNotContainsString( '<script', $html );
		$this->assertStringNotContainsString( 'onload=', $html );
		$this->assertStringNotContainsString( 'onclick=', $html );
	}

	// ─── XSS escaping ───────────────────────────────────────────────────────────

	public function test_dangerous_chars_in_client_name_are_escaped(): void {
		$html = ConsentScreenRenderer::build_html( $this->params( array(
			'client_name' => '<script>alert(1)</script>',
		) ) );
		$this->assertStringNotContainsString( '<script>alert(1)</script>', $html );
		$this->assertStringContainsString( '&lt;script&gt;', $html );
	}

	public function test_dangerous_chars_in_state_are_escaped_in_hidden_input(): void {
		$html = ConsentScreenRenderer::build_html( $this->params( array(
			'state' => 'state"><script>alert(1)</script>',
		) ) );
		$this->assertStringNotContainsString( '"><script>alert(1)', $html );
	}

	// ─── Action buttons ─────────────────────────────────────────────────────────

	public function test_html_renders_authorize_and_deny_buttons(): void {
		$html = $this->collapse_ws( ConsentScreenRenderer::build_html( $this->params() ) );
		$this->assertStringContainsString( 'name="' . ConsentScreenRenderer::DECISION_FIELD . '" value="' . ConsentScreenRenderer::DECISION_AUTHORIZE . '"', $html );
		$this->assertStringContainsString( 'name="' . ConsentScreenRenderer::DECISION_FIELD . '" value="' . ConsentScreenRenderer::DECISION_DENY . '"', $html );
	}

	/** Collapse whitespace runs to a single space — lets attribute-order assertions ignore tab/newline alignment. */
	private function collapse_ws( string $html ): string {
		return (string) preg_replace( '/\s+/', ' ', $html );
	}

	// ─── Notice copy reflects the consent reason ────────────────────────────────

	public function test_silent_cap_decision_shows_reauth_notice(): void {
		$decision = new ConsentDecision(
			ConsentDecision::RENDER_FULL,
			array( 'abilities:content:read' ),
			array( 'abilities:content:read' ),
			array(),
			array(),
			'silent_cap_exceeded'
		);
		$html = ConsentScreenRenderer::build_html( $this->params( array( 'decision' => $decision ) ) );
		$this->assertStringContainsString( 'wp-mcp-consent-notice--reauth', $html );
		$this->assertStringContainsString( 'have not reviewed this bridge', $html );
	}

	public function test_incremental_decision_shows_incremental_notice(): void {
		$decision = new ConsentDecision(
			ConsentDecision::RENDER_INCREMENTAL,
			array( 'abilities:content:read', 'abilities:taxonomies:read' ),
			array( 'abilities:content:read' ),
			array( 'abilities:taxonomies:read' ),
			array(),
			'new_non_sensitive_scopes'
		);
		$html = ConsentScreenRenderer::build_html( $this->params( array( 'decision' => $decision ) ) );
		$this->assertStringContainsString( 'wp-mcp-consent-notice--incremental', $html );
		$this->assertStringContainsString( 'additional permissions', $html );
	}

	// ─── Error renderer ─────────────────────────────────────────────────────────

	public function test_build_error_html_contains_title_and_detail(): void {
		$html = ConsentScreenRenderer::build_error_html( 'Authorization request invalid', 'redirect_uri is not registered for this client.' );
		$this->assertStringContainsString( 'Authorization request invalid', $html );
		$this->assertStringContainsString( 'redirect_uri is not registered', $html );
		$this->assertStringContainsString( 'wp-mcp-consent-shell--error', $html );
	}

	public function test_build_error_html_escapes_user_supplied_strings(): void {
		$html = ConsentScreenRenderer::build_error_html( 'Bad input', '<script>alert(1)</script>' );
		$this->assertStringNotContainsString( '<script>alert(1)</script>', $html );
		$this->assertStringContainsString( '&lt;script&gt;', $html );
	}
}
