<?php
/**
 * Boot-contract regression guard for the default server (Issue #87 S3).
 *
 * The default server's `server_description` advertises a boot_sequence whose
 * `first_tool` is the documented onboarding entrypoint. If that tool name is
 * not also present in the server's `tools` allowlist, tools/call resolves to
 * `-32003 Tool not found` — an advertised-but-unregistered boot path (the #87
 * S3 regression). This test pins the two in sync via a static source parse so
 * it cannot silently drift again.
 *
 * @package WickedEvolutions\McpAdapter\Tests
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\Tests\Unit\Servers;

use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class DefaultServerFactoryBootContractTest extends TestCase {

	private function factory_source(): string {
		return (string) file_get_contents(
			dirname( __DIR__, 3 ) . '/src/Servers/DefaultServerFactory.php'
		);
	}

	public function test_advertised_boot_first_tool_is_in_the_tools_allowlist(): void {
		$src = $this->factory_source();

		$this->assertSame(
			1,
			preg_match( '/"first_tool":"([^"]+)"/', $src, $boot ),
			'server_description must advertise a boot_sequence.first_tool'
		);
		$advertised = $boot[1];

		$this->assertSame(
			1,
			preg_match( "/'tools'\\s*=>\\s*array\\((.*?)\\n\\s*\\),/s", $src, $tools ),
			'DefaultServerFactory must declare a tools allowlist'
		);
		preg_match_all( "/'([^']+)'/", $tools[1], $registered );
		$registered_tools = $registered[1];

		$this->assertContains(
			$advertised,
			$registered_tools,
			sprintf(
				'Advertised boot tool "%s" must be in the default server tools allowlist [%s] — '
				. 'otherwise tools/call returns -32003 Tool not found (Issue #87 S3).',
				$advertised,
				implode( ', ', $registered_tools )
			)
		);
	}
}
