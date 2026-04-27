<?php
/**
 * Regression test: OAuth helper functions must live in the global namespace.
 *
 * Phase 6 hotfix: an earlier build placed the helpers inside the
 * WickedEvolutions\McpAdapter\Auth\OAuth namespace, which caused live
 * 500 errors on first DCR (`Call to undefined function oauth_client_ip`)
 * because callers using `\oauth_client_ip()` resolved to the global namespace
 * but the function only existed inside the OAuth namespace.
 *
 * This test asserts the helpers exist in global, not in the OAuth namespace.
 *
 * @package WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Auth\OAuth;

use PHPUnit\Framework\TestCase;

final class HelpersAreGlobalTest extends TestCase {

	private const HELPERS = [
		'oauth_client_ip',
		'oauth_is_https',
		'oauth_read_auth_header',
		'oauth_log_boundary',
		'token_error',
		'token_success',
	];

	/** @dataProvider helper_names */
	public function test_helper_exists_in_global_namespace( string $name ): void {
		$this->assertTrue(
			function_exists( '\\' . $name ),
			"OAuth helper {$name}() must be defined in the global namespace. " .
			"If this fails, the helper has drifted into a namespaced context — " .
			"check src/Auth/OAuth/helpers.php has no namespace declaration."
		);
	}

	/** @dataProvider helper_names */
	public function test_helper_not_in_oauth_namespace( string $name ): void {
		$this->assertFalse(
			function_exists( 'WickedEvolutions\\McpAdapter\\Auth\\OAuth\\' . $name ),
			"OAuth helper {$name}() must NOT exist inside the OAuth namespace. " .
			"Phase 6 regression: helpers in the namespace caused live 500s when " .
			"callers used \\{$name}() to force global resolution."
		);
	}

	public static function helper_names(): array {
		return array_map( fn( $h ) => [ $h ], self::HELPERS );
	}
}
