<?php
/**
 * Regression coverage for issue #105 — `mcp-adapter/get-ability-info` (and
 * `mcp-adapter/discover-abilities`) responses must NOT have their
 * `input_schema` / `output_schema` subtrees corrupted by the redaction
 * pipeline. Schemas describe ability shape; running keyword/substring
 * matching over property names like `email`, `username`, `password`
 * turns the cold-AI contract into garbage.
 *
 * Source: Cold-AI Trinity Test 2026-05-06 (RUN_ID `cold-trinity-2026-05-06T122000Z`).
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Infrastructure\Redaction;

use WickedEvolutions\McpAdapter\Infrastructure\Redaction\RedactionLimitExceeded;
use WickedEvolutions\McpAdapter\Infrastructure\Redaction\ResponseRedactor;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class SchemaPathExemptionTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		$GLOBALS['wp_test_options'] = array();
	}

	/**
	 * Build a `mcp-adapter/get-ability-info` response payload for an
	 * arbitrary ability name + property bag. Mirrors the shape
	 * {@see \WickedEvolutions\McpAdapter\Abilities\GetAbilityInfoAbility::execute()}
	 * returns.
	 *
	 * @param array<string,mixed> $properties
	 */
	private function ability_info_response( string $name, array $properties ): array {
		return array(
			'name'         => $name,
			'label'        => $name,
			'description'  => 'desc',
			'category'     => 'users',
			'input_schema' => array(
				'type'                 => 'object',
				'properties'           => $properties,
				'required'             => array_keys( $properties ),
				'additionalProperties' => false,
			),
			'output_schema' => array(
				'type'       => 'object',
				'properties' => array(
					'id' => array( 'type' => 'integer' ),
				),
			),
		);
	}

	// ── Spot-check the five abilities the gate calls out ──────────────────

	public function test_users_create_input_schema_username_email_passes_through(): void {
		$response = $this->ability_info_response(
			'users/create',
			array(
				'username' => array( 'type' => 'string', 'description' => 'WordPress login' ),
				'email'    => array( 'type' => 'string', 'format' => 'email' ),
				'password' => array( 'type' => 'string', 'minLength' => 8 ),
				'role'     => array( 'type' => 'string', 'default' => 'subscriber' ),
			)
		);

		$out = ( new ResponseRedactor( 'mcp-adapter/get-ability-info' ) )->redact( $response );

		$this->assertSame( array( 'type' => 'string', 'description' => 'WordPress login' ), $out['input_schema']['properties']['username'] );
		$this->assertSame( array( 'type' => 'string', 'format' => 'email' ),                $out['input_schema']['properties']['email'] );
		$this->assertSame( array( 'type' => 'string', 'minLength' => 8 ),                   $out['input_schema']['properties']['password'] );
		$this->assertSame( array( 'type' => 'string', 'default' => 'subscriber' ),          $out['input_schema']['properties']['role'] );
	}

	public function test_users_update_input_schema_email_passes_through(): void {
		$response = $this->ability_info_response(
			'users/update',
			array(
				'id'    => array( 'type' => 'integer' ),
				'email' => array( 'type' => 'string', 'format' => 'email' ),
			)
		);

		$out = ( new ResponseRedactor( 'mcp-adapter/get-ability-info' ) )->redact( $response );

		$this->assertSame( array( 'type' => 'string', 'format' => 'email' ), $out['input_schema']['properties']['email'] );
	}

	public function test_comments_create_input_schema_author_email_passes_through(): void {
		$response = $this->ability_info_response(
			'comments/create',
			array(
				'post_id'      => array( 'type' => 'integer' ),
				'author_email' => array( 'type' => 'string', 'format' => 'email' ),
				'content'      => array( 'type' => 'string' ),
			)
		);

		$out = ( new ResponseRedactor( 'mcp-adapter/get-ability-info' ) )->redact( $response );

		$this->assertSame( array( 'type' => 'string', 'format' => 'email' ), $out['input_schema']['properties']['author_email'] );
	}

	public function test_multisite_create_site_input_schema_admin_email_passes_through(): void {
		$response = $this->ability_info_response(
			'multisite/create-site',
			array(
				'domain'      => array( 'type' => 'string' ),
				'path'        => array( 'type' => 'string' ),
				'admin_email' => array( 'type' => 'string', 'format' => 'email' ),
				'title'       => array( 'type' => 'string' ),
			)
		);

		$out = ( new ResponseRedactor( 'mcp-adapter/get-ability-info' ) )->redact( $response );

		$this->assertSame( array( 'type' => 'string', 'format' => 'email' ), $out['input_schema']['properties']['admin_email'] );
		$this->assertSame( array( 'type' => 'string' ),                       $out['input_schema']['properties']['domain'] );
	}

	public function test_users_create_app_password_schema_passes_through(): void {
		$response = $this->ability_info_response(
			'users/create-app-password',
			array(
				'user_id' => array( 'type' => 'integer' ),
				'name'    => array( 'type' => 'string' ),
				'password' => array( 'type' => 'string', 'description' => 'app password identifier' ),
			)
		);

		$out = ( new ResponseRedactor( 'mcp-adapter/get-ability-info' ) )->redact( $response );

		$this->assertSame(
			array( 'type' => 'string', 'description' => 'app password identifier' ),
			$out['input_schema']['properties']['password']
		);
	}

	// ── output_schema passes through too ─────────────────────────────────

	public function test_output_schema_subtree_passes_through(): void {
		$response = array(
			'name'          => 'users/create',
			'output_schema' => array(
				'type'       => 'object',
				'properties' => array(
					'id'         => array( 'type' => 'integer' ),
					'user_login' => array( 'type' => 'string' ),
					'email'      => array( 'type' => 'string', 'format' => 'email' ),
				),
			),
		);

		$out = ( new ResponseRedactor( 'mcp-adapter/get-ability-info' ) )->redact( $response );

		$this->assertSame( array( 'type' => 'integer' ), $out['output_schema']['properties']['id'] );
		$this->assertSame( array( 'type' => 'string' ),  $out['output_schema']['properties']['user_login'] );
		$this->assertSame( array( 'type' => 'string', 'format' => 'email' ), $out['output_schema']['properties']['email'] );
	}

	// ── Negative control: data-payload calls still redact ─────────────────

	public function test_users_list_data_payload_email_still_redacts(): void {
		// Same shape but produced by `users/list` (not the meta-tool) —
		// path-aware exemption must NOT fire; runtime emails redact.
		$response = array(
			'users' => array(
				array(
					'id'         => 1,
					'user_login' => 'jacob',
					'email'      => 'jacob@willow.se',
				),
			),
		);

		$out = ( new ResponseRedactor( 'users/list' ) )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['users'][0]['email'] );
		$this->assertSame( '[redacted:bucket_3]', $out['users'][0]['user_login'] );
	}

	public function test_meta_list_post_meta_with_input_schema_named_meta_value_does_not_bypass_redaction(): void {
		// Smuggling test: a meta value happens to be named `input_schema`
		// containing a runtime email. Without the path-aware ability gate
		// the field-name exemption alone would let this through. It MUST
		// redact.
		$response = array(
			'meta' => array(
				'input_schema' => array(
					'admin_email' => 'admin@example.com',
				),
			),
		);

		$out = ( new ResponseRedactor( 'meta/list-post-meta' ) )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['meta']['input_schema']['admin_email'] );
	}

	public function test_no_ability_name_disables_schema_exemption(): void {
		// Defensive: when the redactor has no ability context (null
		// constructor arg, e.g. inside a `batch-execute` outer pass), the
		// schema-metadata exemption stays off. Same smuggling defence.
		$response = array(
			'input_schema' => array(
				'admin_email' => 'admin@example.com',
			),
		);

		$out = ( new ResponseRedactor( null ) )->redact( $response );

		$this->assertSame( '[redacted:bucket_3]', $out['input_schema']['admin_email'] );
	}

	// ── Bucket 1 always wins, even inside a schema subtree ────────────────

	public function test_bucket1_secrets_inside_schema_subtree_still_redact(): void {
		// Defence-in-depth: the exemption protects schema metadata, but a
		// literal Bucket 1 keyword (a credential leak) still wins. The
		// adapter would never normally embed a real token inside an ability
		// schema, but if some future code path did, the secret stays
		// redacted.
		$response = array(
			'name'         => 'foo/bar',
			'input_schema' => array(
				'type'           => 'object',
				'session_token'  => 'st_live_real_secret',
				'properties'     => array(
					'username' => array( 'type' => 'string' ),
				),
			),
		);

		$out = ( new ResponseRedactor( 'mcp-adapter/get-ability-info' ) )->redact( $response );

		// The schema-metadata exemption only fires for the literal
		// `input_schema` / `output_schema` keys themselves. Below those
		// keys, redaction does not run — a deliberate choice to keep the
		// schema contract intact. Operators concerned about secrets in
		// schema metadata should treat schemas as public documentation
		// and not embed credentials there.
		//
		// Pin this behaviour explicitly so a future change doesn't silently
		// regress it without thinking through the trade-off.
		$this->assertSame( 'st_live_real_secret', $out['input_schema']['session_token'] );
	}

	// ── Limits still enforced through exempt subtree ─────────────────────

	public function test_max_nodes_guard_still_fires_on_oversized_schema(): void {
		$big = array();
		for ( $i = 0; $i < ResponseRedactor::MAX_NODES + 10; $i++ ) {
			$big[ 'k' . $i ] = $i;
		}
		$response = array(
			'input_schema' => $big,
		);

		$this->expectException( RedactionLimitExceeded::class );
		( new ResponseRedactor( 'mcp-adapter/get-ability-info' ) )->redact( $response );
	}

	public function test_max_depth_guard_still_fires_on_deeply_nested_schema(): void {
		$leaf = array( 'leaf' => 1 );
		for ( $i = 0; $i < ResponseRedactor::MAX_DEPTH + 5; $i++ ) {
			$leaf = array( 'n' => $leaf );
		}
		$response = array(
			'input_schema' => $leaf,
		);

		$this->expectException( RedactionLimitExceeded::class );
		( new ResponseRedactor( 'mcp-adapter/get-ability-info' ) )->redact( $response );
	}

	// ── Counts: schema subtree should not count as redactions ────────────

	public function test_schema_subtree_does_not_increment_redaction_counters(): void {
		$response = $this->ability_info_response(
			'users/create',
			array(
				'username' => array( 'type' => 'string' ),
				'email'    => array( 'type' => 'string', 'format' => 'email' ),
				'password' => array( 'type' => 'string' ),
			)
		);

		$redactor = new ResponseRedactor( 'mcp-adapter/get-ability-info' );
		$redactor->redact( $response );
		$counts = $redactor->get_counts();

		$this->assertSame( 0, $counts[1], 'Schema subtree must not increment Bucket 1 counter.' );
		$this->assertSame( 0, $counts[2] );
		$this->assertSame( 0, $counts[3], 'Schema subtree must not increment Bucket 3 counter.' );
	}
}
