<?php
/**
 * AI-callable safety-settings abilities (DB-3).
 *
 * Seven abilities for managing the redaction filter from chat. All abilities
 * require `manage_options`. Bucket 2 weakening and master-toggle changes
 * have NO ability paths — those are Admin-UI only by design.
 *
 * Friction model:
 *   - Strengthen / reverse own additions / restore defaults: zero friction.
 *   - Weaken Bucket 3 default keyword OR exempt ability from Bucket 3:
 *     in-chat 1/2 confirmation token (60s, session-bound, params-bound).
 *
 * Confirmation flow:
 *   1. AI calls ability without `confirmation_token`.
 *   2. Adapter mints a token bound to (session, ability, params) and returns
 *      { confirmation_required: true, token, summary, options[1=yes,2=no] }.
 *   3. AI surfaces the warning + options to the operator.
 *   4. Operator picks 1 → AI re-issues with the token.
 *   5. Adapter consumes the token (one-time, TTL 60s) and executes.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Abilities\Settings;

use WickedEvolutions\McpAdapter\Infrastructure\Observability\BoundaryEventEmitter;
use WickedEvolutions\McpAdapter\Settings\ConfirmationTokenStore;
use WickedEvolutions\McpAdapter\Settings\SafetySettingsRepository as Repo;

/**
 * Registers the seven `settings/*` abilities.
 */
final class SettingsAbilities {

	/**
	 * Hook into `wp_abilities_api_init` to register all settings abilities.
	 */
	public static function register_all(): void {
		self::register_get_redaction_list();
		self::register_add_redaction_keyword();
		self::register_remove_custom_keyword();
		self::register_restore_redaction_defaults();
		self::register_remove_default_bucket3_keyword();
		self::register_exempt_ability_from_bucket3();
		self::register_unexempt_ability_from_bucket3();
	}

	// Permission callback (shared) ---------------------------------------

	public static function check_permission( $input = array() ) {
		if ( ! is_user_logged_in() ) {
			return new \WP_Error( 'authentication_required', 'Settings abilities require an authenticated administrator.' );
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return new \WP_Error( 'insufficient_capability', 'Settings abilities require the manage_options capability.' );
		}
		return true;
	}

	/**
	 * Reject a keyword that is not actually in the Bucket 3 defaults BEFORE
	 * minting a confirmation token. Synthesis Decision 3 forbids weakening
	 * Bucket 2 via chat at any granularity — a Bucket 2 keyword arriving on
	 * the Bucket 3 path must never produce a confirmation prompt.
	 *
	 * Returns null when the keyword is a valid Bucket 3 default and the
	 * caller should proceed. Returns a structured error response array
	 * otherwise; the caller should return it directly.
	 *
	 * @param string $keyword Already lowercased / trimmed.
	 * @return array<string,mixed>|null
	 */
	private static function guard_bucket3_default_keyword( string $keyword ): ?array {
		if ( '' === $keyword ) {
			return array(
				'success'               => false,
				'confirmation_required' => false,
				'message'               => 'Keyword must be a non-empty string.',
			);
		}

		$bucket3 = array_map( 'strtolower', Repo::bucket3_default_keywords() );
		if ( in_array( $keyword, $bucket3, true ) ) {
			return null;
		}

		$bucket2 = array_map( 'strtolower', Repo::bucket2_default_keywords() );
		if ( in_array( $keyword, $bucket2, true ) ) {
			BoundaryEventEmitter::emit(
				null,
				'boundary.confirmation.failed',
				array(
					'severity'   => 'warn',
					'user_id'    => (int) get_current_user_id(),
					'method'     => 'settings/remove-default-bucket3-keyword',
					'error_code' => 'bucket2_keyword_rejected',
					'name'       => sanitize_key( $keyword ),
					'reason'     => 'Bucket 2 weakening is not available via chat — Admin UI only.',
				)
			);
			return array(
				'success'               => false,
				'confirmation_required' => false,
				'message'               => sprintf(
					"'%s' is a Bucket 2 (payment / regulated) keyword. Bucket 2 weakening is not available via chat. To make this change, use WP Admin → Settings → MCP Safety.",
					$keyword
				),
			);
		}

		return array(
			'success'               => false,
			'confirmation_required' => false,
			'message'               => sprintf(
				"'%s' is not in any default redaction list (Bucket 2 or Bucket 3). If it was added as a custom keyword, use settings/remove-custom-keyword instead.",
				$keyword
			),
		);
	}

	/**
	 * Reject an unknown ability name BEFORE minting a confirmation token.
	 *
	 * Returns null when the ability is known (or when the abilities API is
	 * unavailable in this context — fail-open is acceptable here because
	 * exempting a non-existent ability is a no-op at redaction time, just
	 * a UX nuisance). Returns a structured error response otherwise.
	 *
	 * @param string $ability_name
	 * @param string $caller_ability  The ability invoking this guard (for telemetry).
	 * @return array<string,mixed>|null
	 */
	private static function guard_known_ability_name( string $ability_name, string $caller_ability ): ?array {
		if ( '' === $ability_name ) {
			return array(
				'success'               => false,
				'confirmation_required' => false,
				'message'               => 'ability_name must be a non-empty string.',
			);
		}

		// If the WP Abilities API isn't loaded (unit tests without the real
		// plugin), skip the existence check — the repository write itself
		// will accept any sanitised string and the operator can clean up.
		if ( ! function_exists( 'wp_get_ability' ) ) {
			return null;
		}

		$ability = wp_get_ability( $ability_name );
		if ( null !== $ability ) {
			return null;
		}

		BoundaryEventEmitter::emit(
			null,
			'boundary.confirmation.failed',
			array(
				'severity'   => 'warn',
				'user_id'    => (int) get_current_user_id(),
				'method'     => $caller_ability,
				'error_code' => 'unknown_ability_name',
				'name'       => sanitize_text_field( $ability_name ),
				'reason'     => 'No ability registered under this name.',
			)
		);

		return array(
			'success'               => false,
			'confirmation_required' => false,
			'message'               => sprintf(
				"No ability registered under the name '%s'. Use settings/get-redaction-list or the discover-abilities tool to find the correct ability name.",
				$ability_name
			),
		);
	}

	// settings/get-redaction-list ----------------------------------------

	private static function register_get_redaction_list(): void {
		wp_register_ability(
			'settings/get-redaction-list',
			array(
				'label'               => 'Get redaction list',
				'description'         => 'Read the current redaction configuration: master toggle, bucket-1/2/3 keyword lists, per-ability exemptions. No friction.',
				'category'            => 'mcp-adapter',
				'input_schema'        => array( 'type' => 'object' ),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'master_enabled'      => array( 'type' => 'boolean' ),
						'bucket1'             => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
						'bucket2'             => array(
							'type'       => 'object',
							'properties' => array(
								'active'  => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
								'custom'  => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
								'removed' => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
							),
						),
						'bucket3'             => array(
							'type'       => 'object',
							'properties' => array(
								'active'  => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
								'custom'  => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
								'removed' => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
							),
						),
						'exemptions_bucket3'  => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
						'exemptions_bucket2'  => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
					),
				),
				'permission_callback' => array( self::class, 'check_permission' ),
				'execute_callback'    => array( self::class, 'execute_get_redaction_list' ),
				'meta'                => array(
					'mcp'         => array( 'public' => true ),
					'show_in_rest' => true,
					'annotations' => array(
						'readonly'    => true,
						'destructive' => false,
						'idempotent'  => true,
					),
				),
			)
		);
	}

	public static function execute_get_redaction_list( $input = array() ): array {
		return array(
			'master_enabled'     => Repo::is_master_enabled(),
			'bucket1'            => Repo::bucket1_default_keywords(),
			'bucket2'            => array(
				'active'  => Repo::get_active_keywords( Repo::BUCKET_PAYMENT ),
				'custom'  => Repo::get_custom_keywords( Repo::BUCKET_PAYMENT ),
				'removed' => Repo::get_removed_defaults( Repo::BUCKET_PAYMENT ),
			),
			'bucket3'            => array(
				'active'  => Repo::get_active_keywords( Repo::BUCKET_CONTACT ),
				'custom'  => Repo::get_custom_keywords( Repo::BUCKET_CONTACT ),
				'removed' => Repo::get_removed_defaults( Repo::BUCKET_CONTACT ),
			),
			'exemptions_bucket3' => Repo::get_exemptions( Repo::BUCKET_CONTACT ),
			'exemptions_bucket2' => Repo::get_exemptions( Repo::BUCKET_PAYMENT ),
		);
	}

	// settings/add-redaction-keyword (no friction) -----------------------

	private static function register_add_redaction_keyword(): void {
		wp_register_ability(
			'settings/add-redaction-keyword',
			array(
				'label'               => 'Add redaction keyword',
				'description'         => 'Add a custom keyword to Bucket 2 (payment / regulated) or Bucket 3 (contact PII). Strengthens defaults — no confirmation required. Bucket 1 is hardcoded and not addable.',
				'category'            => 'mcp-adapter',
				'input_schema'        => array(
					'type'       => 'object',
					'required'   => array( 'keyword', 'bucket' ),
					'properties' => array(
						'keyword' => array( 'type' => 'string', 'description' => 'Field-name keyword to redact (lower-cased automatically).' ),
						'bucket'  => array( 'type' => 'integer', 'enum' => array( 2, 3 ) ),
					),
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'success' => array( 'type' => 'boolean' ),
						'added'   => array( 'type' => 'boolean' ),
						'message' => array( 'type' => 'string' ),
					),
				),
				'permission_callback' => array( self::class, 'check_permission' ),
				'execute_callback'    => array( self::class, 'execute_add_redaction_keyword' ),
				'meta'                => array(
					'mcp'         => array( 'public' => true ),
					'show_in_rest' => true,
					'annotations' => array(
						'readonly'    => false,
						'destructive' => false,
						'idempotent'  => true,
					),
				),
			)
		);
	}

	public static function execute_add_redaction_keyword( $input = array() ): array {
		$keyword = isset( $input['keyword'] ) ? (string) $input['keyword'] : '';
		$bucket  = isset( $input['bucket'] ) ? (int) $input['bucket'] : 0;

		$result = Repo::add_custom_keyword( $bucket, $keyword );
		if ( is_wp_error( $result ) ) {
			return array(
				'success' => false,
				'added'   => false,
				'message' => $result->get_error_message(),
			);
		}

		BoundaryEventEmitter::emit(
			null,
			'boundary.redaction_keywords.changed',
			array(
				'severity'  => 'info',
				'user_id'   => (int) get_current_user_id(),
				'reason'    => 'add_custom',
				'name'      => sanitize_key( $keyword ),
				'dimension' => 'bucket_' . $bucket,
				'method'    => 'settings/add-redaction-keyword',
			)
		);

		return array(
			'success' => true,
			'added'   => (bool) $result,
			'message' => $result ? 'Keyword added.' : 'Keyword already present.',
		);
	}

	// settings/remove-custom-keyword (no friction) -----------------------

	private static function register_remove_custom_keyword(): void {
		wp_register_ability(
			'settings/remove-custom-keyword',
			array(
				'label'               => 'Remove custom redaction keyword',
				'description'         => 'Reverse a previously-added custom keyword (Bucket 2 or 3). Reversal of operator additions only — does not remove default keywords. No confirmation required.',
				'category'            => 'mcp-adapter',
				'input_schema'        => array(
					'type'       => 'object',
					'required'   => array( 'keyword', 'bucket' ),
					'properties' => array(
						'keyword' => array( 'type' => 'string' ),
						'bucket'  => array( 'type' => 'integer', 'enum' => array( 2, 3 ) ),
					),
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'success' => array( 'type' => 'boolean' ),
						'removed' => array( 'type' => 'boolean' ),
						'message' => array( 'type' => 'string' ),
					),
				),
				'permission_callback' => array( self::class, 'check_permission' ),
				'execute_callback'    => array( self::class, 'execute_remove_custom_keyword' ),
				'meta'                => array(
					'mcp'         => array( 'public' => true ),
					'show_in_rest' => true,
					'annotations' => array(
						'readonly'    => false,
						'destructive' => false,
						'idempotent'  => true,
					),
				),
			)
		);
	}

	public static function execute_remove_custom_keyword( $input = array() ): array {
		$keyword = isset( $input['keyword'] ) ? (string) $input['keyword'] : '';
		$bucket  = isset( $input['bucket'] ) ? (int) $input['bucket'] : 0;

		$result = Repo::remove_custom_keyword( $bucket, $keyword );
		if ( is_wp_error( $result ) ) {
			return array(
				'success' => false,
				'removed' => false,
				'message' => $result->get_error_message(),
			);
		}

		BoundaryEventEmitter::emit(
			null,
			'boundary.redaction_keywords.changed',
			array(
				'severity'  => 'info',
				'user_id'   => (int) get_current_user_id(),
				'reason'    => 'remove_custom',
				'name'      => sanitize_key( $keyword ),
				'dimension' => 'bucket_' . $bucket,
				'method'    => 'settings/remove-custom-keyword',
			)
		);

		return array(
			'success' => true,
			'removed' => (bool) $result,
			'message' => $result ? 'Custom keyword removed.' : 'Keyword was not in the custom list.',
		);
	}

	// settings/restore-redaction-defaults (no friction) ------------------

	private static function register_restore_redaction_defaults(): void {
		wp_register_ability(
			'settings/restore-redaction-defaults',
			array(
				'label'               => 'Restore redaction defaults',
				'description'         => 'Restore Bucket 2 + Bucket 3 redaction lists to factory defaults. Clears custom additions and removed-defaults. No confirmation required (strengthens safety).',
				'category'            => 'mcp-adapter',
				'input_schema'        => array( 'type' => 'object' ),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'success' => array( 'type' => 'boolean' ),
						'message' => array( 'type' => 'string' ),
					),
				),
				'permission_callback' => array( self::class, 'check_permission' ),
				'execute_callback'    => array( self::class, 'execute_restore_redaction_defaults' ),
				'meta'                => array(
					'mcp'         => array( 'public' => true ),
					'show_in_rest' => true,
					'annotations' => array(
						'readonly'    => false,
						'destructive' => false,
						'idempotent'  => true,
					),
				),
			)
		);
	}

	public static function execute_restore_redaction_defaults( $input = array() ): array {
		Repo::restore_defaults();

		BoundaryEventEmitter::emit(
			null,
			'boundary.redaction_keywords.changed',
			array(
				'severity'  => 'info',
				'user_id'   => (int) get_current_user_id(),
				'reason'    => 'restore_defaults',
				'method'    => 'settings/restore-redaction-defaults',
			)
		);

		return array(
			'success' => true,
			'message' => 'Redaction lists restored to defaults.',
		);
	}

	// settings/remove-default-bucket3-keyword (1/2 confirmation) ---------

	private static function register_remove_default_bucket3_keyword(): void {
		wp_register_ability(
			'settings/remove-default-bucket3-keyword',
			array(
				'label'               => 'Remove default Bucket 3 keyword',
				'description'         => 'Weaken the default Bucket 3 redaction list by removing a default keyword. Requires in-chat 1/2 confirmation. Bucket 2 default removal is not available via abilities — it is admin-UI only.',
				'category'            => 'mcp-adapter',
				'input_schema'        => array(
					'type'       => 'object',
					'required'   => array( 'keyword' ),
					'properties' => array(
						'keyword'            => array( 'type' => 'string' ),
						'confirmation_token' => array( 'type' => 'string', 'description' => 'One-time token returned by the first call. Required on the second call.' ),
					),
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'success'                => array( 'type' => 'boolean' ),
						'confirmation_required'  => array( 'type' => 'boolean' ),
						'token'                  => array( 'type' => 'string' ),
						'summary'                => array( 'type' => 'string' ),
						'options'                => array( 'type' => 'array' ),
						'message'                => array( 'type' => 'string' ),
					),
				),
				'permission_callback' => array( self::class, 'check_permission' ),
				'execute_callback'    => array( self::class, 'execute_remove_default_bucket3_keyword' ),
				'meta'                => array(
					'mcp'         => array( 'public' => true ),
					'show_in_rest' => true,
					'annotations' => array(
						'readonly'    => false,
						'destructive' => true,
						'idempotent'  => false,
					),
				),
			)
		);
	}

	public static function execute_remove_default_bucket3_keyword( $input = array() ): array {
		$keyword = isset( $input['keyword'] ) ? (string) $input['keyword'] : '';
		$token   = isset( $input['confirmation_token'] ) ? (string) $input['confirmation_token'] : '';

		$ability = 'settings/remove-default-bucket3-keyword';
		$params  = array( 'keyword' => strtolower( trim( $keyword ) ) );

		// Bucket-membership pre-check (synthesis Decision 3).
		// Bucket 2 cannot be weakened through chat at any granularity.
		// Reject before minting a token so the operator is never shown a
		// confirmation prompt for a keyword that doesn't belong here.
		$bucket_check = self::guard_bucket3_default_keyword( $params['keyword'] );
		if ( null !== $bucket_check ) {
			return $bucket_check;
		}

		if ( '' === $token ) {
			$session = ConfirmationTokenStore::current_session_id();
			$minted  = ConfirmationTokenStore::mint( $session, $ability, $params );

			return array(
				'success'               => false,
				'confirmation_required' => true,
				'token'                 => $minted,
				'summary'               => sprintf(
					"Remove '%s' from Bucket 3 redaction defaults — exposes this contact field in all subsequent ability responses until re-added. This weakens the default safety posture.",
					$params['keyword']
				),
				'options'               => array(
					array( 'key' => '1', 'label' => 'Yes, confirm' ),
					array( 'key' => '2', 'label' => 'No' ),
				),
				'message'               => 'Confirmation required. Re-issue the call with this token within 60 seconds.',
			);
		}

		$session = ConfirmationTokenStore::current_session_id();
		$consume = ConfirmationTokenStore::consume( $token, $session, $ability, $params );
		if ( is_wp_error( $consume ) ) {
			BoundaryEventEmitter::emit(
				null,
				'boundary.confirmation.failed',
				array(
					'severity'   => 'warn',
					'user_id'    => (int) get_current_user_id(),
					'method'     => $ability,
					'error_code' => $consume->get_error_code(),
					'reason'     => $consume->get_error_message(),
				)
			);
			return array(
				'success'               => false,
				'confirmation_required' => false,
				'message'               => $consume->get_error_message(),
			);
		}

		$result = Repo::remove_default_keyword( Repo::BUCKET_CONTACT, $keyword );
		if ( is_wp_error( $result ) ) {
			return array(
				'success'               => false,
				'confirmation_required' => false,
				'message'               => $result->get_error_message(),
			);
		}

		BoundaryEventEmitter::emit(
			null,
			'boundary.redaction_keywords.changed',
			array(
				'severity'  => 'warn',
				'user_id'   => (int) get_current_user_id(),
				'reason'    => 'remove_default',
				'name'      => sanitize_key( $keyword ),
				'dimension' => 'bucket_3',
				'method'    => $ability,
			)
		);

		return array(
			'success'               => true,
			'confirmation_required' => false,
			'message'               => $result
				? 'Default keyword removed. Use settings/restore-redaction-defaults or add-redaction-keyword to re-enable.'
				: 'Keyword was already removed.',
		);
	}

	// settings/exempt-ability-from-bucket3 (1/2 confirmation) ------------

	private static function register_exempt_ability_from_bucket3(): void {
		wp_register_ability(
			'settings/exempt-ability-from-bucket3',
			array(
				'label'               => 'Exempt ability from Bucket 3 redaction',
				'description'         => 'Allow contact PII (email, phone, address, IP) to flow through one specific ability\'s response. Requires in-chat 1/2 confirmation. Bucket 2 exemptions are admin-UI only.',
				'category'            => 'mcp-adapter',
				'input_schema'        => array(
					'type'       => 'object',
					'required'   => array( 'ability_name' ),
					'properties' => array(
						'ability_name'       => array( 'type' => 'string', 'description' => 'Namespaced ability name (e.g. "users/list").' ),
						'confirmation_token' => array( 'type' => 'string' ),
					),
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'success'               => array( 'type' => 'boolean' ),
						'confirmation_required' => array( 'type' => 'boolean' ),
						'token'                 => array( 'type' => 'string' ),
						'summary'               => array( 'type' => 'string' ),
						'options'               => array( 'type' => 'array' ),
						'message'               => array( 'type' => 'string' ),
					),
				),
				'permission_callback' => array( self::class, 'check_permission' ),
				'execute_callback'    => array( self::class, 'execute_exempt_ability_from_bucket3' ),
				'meta'                => array(
					'mcp'         => array( 'public' => true ),
					'show_in_rest' => true,
					'annotations' => array(
						'readonly'    => false,
						'destructive' => true,
						'idempotent'  => false,
					),
				),
			)
		);
	}

	public static function execute_exempt_ability_from_bucket3( $input = array() ): array {
		$ability_name = isset( $input['ability_name'] ) ? (string) $input['ability_name'] : '';
		$token        = isset( $input['confirmation_token'] ) ? (string) $input['confirmation_token'] : '';

		$ability = 'settings/exempt-ability-from-bucket3';
		$params  = array( 'ability_name' => trim( $ability_name ) );

		// Reject unknown ability names BEFORE minting a confirmation token —
		// otherwise the operator is shown a confirmation for a no-op write.
		$ability_check = self::guard_known_ability_name( $params['ability_name'], $ability );
		if ( null !== $ability_check ) {
			return $ability_check;
		}

		if ( '' === $token ) {
			$session = ConfirmationTokenStore::current_session_id();
			$minted  = ConfirmationTokenStore::mint( $session, $ability, $params );

			return array(
				'success'               => false,
				'confirmation_required' => true,
				'token'                 => $minted,
				'summary'               => sprintf(
					"Exempt '%s' from Bucket 3 redaction — its responses will return contact PII (email, phone, address, IP) un-redacted. This weakens the default safety posture for this specific ability only.",
					$params['ability_name']
				),
				'options'               => array(
					array( 'key' => '1', 'label' => 'Yes, confirm' ),
					array( 'key' => '2', 'label' => 'No' ),
				),
				'message'               => 'Confirmation required. Re-issue the call with this token within 60 seconds.',
			);
		}

		$session = ConfirmationTokenStore::current_session_id();
		$consume = ConfirmationTokenStore::consume( $token, $session, $ability, $params );
		if ( is_wp_error( $consume ) ) {
			BoundaryEventEmitter::emit(
				null,
				'boundary.confirmation.failed',
				array(
					'severity'   => 'warn',
					'user_id'    => (int) get_current_user_id(),
					'method'     => $ability,
					'error_code' => $consume->get_error_code(),
					'reason'     => $consume->get_error_message(),
				)
			);
			return array(
				'success'               => false,
				'confirmation_required' => false,
				'message'               => $consume->get_error_message(),
			);
		}

		$result = Repo::add_exemption( Repo::BUCKET_CONTACT, $ability_name );
		if ( is_wp_error( $result ) ) {
			return array(
				'success'               => false,
				'confirmation_required' => false,
				'message'               => $result->get_error_message(),
			);
		}

		BoundaryEventEmitter::emit(
			null,
			'boundary.ability_exemption.changed',
			array(
				'severity'  => 'warn',
				'user_id'   => (int) get_current_user_id(),
				'reason'    => 'add',
				'name'      => sanitize_text_field( $ability_name ),
				'dimension' => 'bucket_3',
				'method'    => $ability,
			)
		);

		return array(
			'success'               => true,
			'confirmation_required' => false,
			'message'               => $result
				? 'Ability exempted from Bucket 3 redaction.'
				: 'Ability was already exempt.',
		);
	}

	// settings/unexempt-ability-from-bucket3 (no friction) ---------------

	private static function register_unexempt_ability_from_bucket3(): void {
		wp_register_ability(
			'settings/unexempt-ability-from-bucket3',
			array(
				'label'               => 'Re-lock ability under Bucket 3',
				'description'         => 'Remove a previously-granted Bucket 3 exemption. Strengthens safety — no confirmation required.',
				'category'            => 'mcp-adapter',
				'input_schema'        => array(
					'type'       => 'object',
					'required'   => array( 'ability_name' ),
					'properties' => array(
						'ability_name' => array( 'type' => 'string' ),
					),
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'success' => array( 'type' => 'boolean' ),
						'removed' => array( 'type' => 'boolean' ),
						'message' => array( 'type' => 'string' ),
					),
				),
				'permission_callback' => array( self::class, 'check_permission' ),
				'execute_callback'    => array( self::class, 'execute_unexempt_ability_from_bucket3' ),
				'meta'                => array(
					'mcp'         => array( 'public' => true ),
					'show_in_rest' => true,
					'annotations' => array(
						'readonly'    => false,
						'destructive' => false,
						'idempotent'  => true,
					),
				),
			)
		);
	}

	public static function execute_unexempt_ability_from_bucket3( $input = array() ): array {
		$ability_name = isset( $input['ability_name'] ) ? (string) $input['ability_name'] : '';

		$result = Repo::remove_exemption( Repo::BUCKET_CONTACT, $ability_name );
		if ( is_wp_error( $result ) ) {
			return array(
				'success' => false,
				'removed' => false,
				'message' => $result->get_error_message(),
			);
		}

		BoundaryEventEmitter::emit(
			null,
			'boundary.ability_exemption.changed',
			array(
				'severity'  => 'info',
				'user_id'   => (int) get_current_user_id(),
				'reason'    => 'remove',
				'name'      => sanitize_text_field( $ability_name ),
				'dimension' => 'bucket_3',
				'method'    => 'settings/unexempt-ability-from-bucket3',
			)
		);

		return array(
			'success' => true,
			'removed' => (bool) $result,
			'message' => $result ? 'Bucket 3 exemption removed.' : 'Ability was not exempt.',
		);
	}
}
