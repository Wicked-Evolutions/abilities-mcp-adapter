<?php
/**
 * Rate-limit burst harness — operator CLI tool (#27).
 *
 * Bursts a tight series of MCP JSON-RPC requests at a live endpoint and
 * verifies the limiter trips at the configured threshold with a 429 +
 * Retry-After response. Pairs with the `RateLimiter` unit tests, which
 * cover the in-memory math; this script covers the wire behavior.
 *
 * Usage:
 *   php bin/rate-limit-burst.php \
 *       --base-url=https://example.com \
 *       --case=threshold-trip \
 *       [--bursts=65] \
 *       [--threshold=60] \
 *       [--bearer=TOKEN] \
 *       [--header='X-Forwarded-For: 198.51.100.7'] \
 *       [--verbose]
 *
 * Cases:
 *   threshold-trip      Burst N tools/call requests; expect 60 OK then 429.
 *   initialize-window   Burst N initialize requests; expect 30 OK then 429.
 *
 * Exit code:
 *   0 — burst behaved as expected.
 *   1 — a wire-level assertion failed (no 429, premature 429, missing Retry-After, …).
 *   2 — usage error.
 *   3 — transport error (DNS, connection refused, TLS).
 *
 * Multi-IP / proxy-trust matrix coverage:
 *   - Per-IP separation: run twice from different source IPs (e.g. two VPSes,
 *     or `--header='X-Forwarded-For: ...'` on a host where
 *     `mcp_adapter_trust_forwarded_host` is enabled). Each source should get
 *     an independent 60/min budget.
 *   - Trusted-proxy: with the trust filter OFF, X-Forwarded-For should be
 *     ignored and REMOTE_ADDR should be the bucketing key. Run the same
 *     burst from one source while spoofing X-Forwarded-For — expect the
 *     trip to land in the same bucket regardless of the spoofed header.
 *
 * Boundary log verification:
 *   On the WP side, after the burst, query `kl_boundary` for entries with
 *   `event = 'rate_limit_hit'`, recent timestamps, and the expected
 *   dimension/method/limit/window tags. The harness does not run this
 *   query itself (no DB credentials in the harness's threat model) but
 *   prints the WP-CLI command an operator can run.
 *
 * Copyright (C) 2026 Wicked Evolutions
 * License: GPL-2.0-or-later
 */

declare( strict_types=1 );

if ( PHP_SAPI !== 'cli' ) {
	fwrite( STDERR, "rate-limit-burst harness must run from the CLI.\n" );
	exit( 2 );
}

require_once dirname( __DIR__ ) . '/vendor/autoload.php';

use WickedEvolutions\McpAdapter\RateLimit\BurstHarness;

/** Parse `--key=value` style argv. */
function parse_args( array $argv ): array {
	$out = array(
		'base-url'  => '',
		'case'      => 'threshold-trip',
		'bursts'    => 0,
		'threshold' => 0,
		'bearer'    => '',
		'headers'   => array(),
		'verbose'   => false,
		'help'      => false,
	);
	foreach ( array_slice( $argv, 1 ) as $arg ) {
		if ( $arg === '--help' || $arg === '-h' ) {
			$out['help'] = true;
			continue;
		}
		if ( $arg === '--verbose' || $arg === '-v' ) {
			$out['verbose'] = true;
			continue;
		}
		if ( strpos( $arg, '--header=' ) === 0 ) {
			$out['headers'][] = substr( $arg, 9 );
			continue;
		}
		if ( strpos( $arg, '--' ) === 0 && false !== strpos( $arg, '=' ) ) {
			[ $k, $v ] = explode( '=', substr( $arg, 2 ), 2 );
			if ( 'bursts' === $k || 'threshold' === $k ) {
				$out[ $k ] = (int) $v;
			} else {
				$out[ $k ] = $v;
			}
		}
	}
	return $out;
}

function usage(): void {
	echo <<<USAGE
Rate-limit burst harness (#27)

Usage:
  php bin/rate-limit-burst.php --base-url=URL --case=CASE [options]

Required:
  --base-url=URL     Site base URL, e.g. https://example.com

Cases (--case):
  threshold-trip     Burst tools/call until limiter trips. Default threshold 60.
  initialize-window  Burst initialize until limiter trips. Default threshold 30.

Optional:
  --bursts=N         Number of requests to fire (default: threshold + 5).
  --threshold=N      Override expected limit (defaults per case).
  --bearer=TOKEN     OAuth Bearer token for authenticated bursts (post-Phase B).
  --header='K: V'    Extra header on every request (repeatable). Use for
                     X-Forwarded-For spoof tests against the proxy-trust matrix.
  --verbose          Print per-request status + headers.
  --help             Show this message.

Exit codes:
  0  burst matched expected behavior
  1  assertion failed (no 429, premature 429, missing Retry-After, ...)
  2  usage error
  3  transport error

USAGE;
}

/**
 * Perform one curl request and return parsed response + transport error string (if any).
 *
 * @return array{response: array, error: string}
 */
function send( string $url, string $method, string $body, array $headers ): array {
	$ch = curl_init();
	curl_setopt( $ch, CURLOPT_URL, $url );
	curl_setopt( $ch, CURLOPT_CUSTOMREQUEST, $method );
	if ( '' !== $body ) {
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $body );
	}
	curl_setopt( $ch, CURLOPT_HTTPHEADER, $headers );
	curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
	curl_setopt( $ch, CURLOPT_HEADER, true );
	curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 10 );
	curl_setopt( $ch, CURLOPT_TIMEOUT, 30 );
	curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, false );
	$raw = curl_exec( $ch );
	$err = curl_error( $ch );
	curl_close( $ch );

	if ( ! is_string( $raw ) ) {
		return array( 'response' => array( 'status' => 0, 'headers' => array(), 'body' => '' ), 'error' => $err ?: 'curl returned non-string' );
	}
	return array( 'response' => BurstHarness::parse_response( $raw ), 'error' => '' );
}

/** Compose curl-style header lines from an associative session pair + extras. */
function compose_headers( array $session, string $bearer, array $extras ): array {
	$headers = array(
		'Content-Type: application/json',
		'Accept: application/json',
	);
	if ( ! empty( $session['session_id'] ) ) {
		$headers[] = 'Mcp-Session-Id: ' . $session['session_id'];
	}
	if ( ! empty( $session['session_token'] ) ) {
		$headers[] = 'Mcp-Session-Token: ' . $session['session_token'];
	}
	if ( '' !== $bearer ) {
		$headers[] = 'Authorization: Bearer ' . $bearer;
	}
	foreach ( $extras as $h ) {
		$headers[] = $h;
	}
	return $headers;
}

$opts = parse_args( $argv );
if ( $opts['help'] || '' === $opts['base-url'] ) {
	usage();
	exit( '' === $opts['base-url'] && ! $opts['help'] ? 2 : 0 );
}

$url       = rtrim( $opts['base-url'], '/' ) . '/wp-json/mcp/mcp-adapter-default-server';
$case      = $opts['case'];
$threshold = $opts['threshold'] > 0
	? $opts['threshold']
	: ( 'initialize-window' === $case ? BurstHarness::DEFAULT_INITIALIZE_THRESHOLD : BurstHarness::DEFAULT_THRESHOLD );
$bursts    = $opts['bursts'] > 0 ? $opts['bursts'] : $threshold + 5;
$session   = array( 'session_id' => null, 'session_token' => null );

if ( ! in_array( $case, array( 'threshold-trip', 'initialize-window' ), true ) ) {
	fwrite( STDERR, "Unknown case: {$case}\n" );
	usage();
	exit( 2 );
}

// Initialize the session unless we're stress-testing initialize itself.
if ( 'threshold-trip' === $case ) {
	$body    = BurstHarness::build_initialize_body( 1 );
	$headers = compose_headers( $session, $opts['bearer'], $opts['headers'] );
	$result  = send( $url, 'POST', $body, $headers );
	if ( '' !== $result['error'] ) {
		fwrite( STDERR, "Transport error during initialize: {$result['error']}\n" );
		exit( 3 );
	}
	if ( $result['response']['status'] >= 400 ) {
		fwrite( STDERR, "Initialize failed with status {$result['response']['status']}; cannot proceed.\n" );
		exit( 3 );
	}
	$session = BurstHarness::merge_session( $session, BurstHarness::extract_session( $result['response'] ) );
	if ( $opts['verbose'] ) {
		echo "initialize OK — session_id={$session['session_id']}\n";
	}
}

// Burst.
$results = array();
for ( $i = 0; $i < $bursts; $i++ ) {
	$rid     = $i + 100;
	$body    = 'initialize-window' === $case
		? BurstHarness::build_initialize_body( $rid )
		: BurstHarness::build_tools_call_body( $rid );
	$headers = compose_headers( $session, $opts['bearer'], $opts['headers'] );
	$result  = send( $url, 'POST', $body, $headers );

	if ( '' !== $result['error'] ) {
		fwrite( STDERR, "Transport error at burst index {$i}: {$result['error']}\n" );
		exit( 3 );
	}

	$status      = (int) $result['response']['status'];
	$retry_after = isset( $result['response']['headers']['retry-after'] )
		? (int) $result['response']['headers']['retry-after']
		: null;

	$results[] = array( 'status' => $status, 'retry_after' => $retry_after );

	$session = BurstHarness::merge_session( $session, BurstHarness::extract_session( $result['response'] ) );

	if ( $opts['verbose'] ) {
		printf( "[%3d] HTTP %d  retry_after=%s\n", $i, $status, $retry_after === null ? '-' : (string) $retry_after );
	}
}

$verdict = BurstHarness::classify_threshold_trip( $results, $threshold );

echo json_encode( array(
	'case'            => $case,
	'threshold'       => $threshold,
	'bursts'          => $bursts,
	'first_429_index' => $verdict['first_429_index'],
	'passed'          => $verdict['passed'],
	'reasons'         => $verdict['reasons'],
), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";

if ( ! $verdict['passed'] ) {
	exit( 1 );
}

echo "\nVerify boundary log on the server:\n";
echo "  wp eval 'global \$wpdb; var_export(\$wpdb->get_results(\n";
echo "    \"SELECT event, tags, created_at FROM \" . \$wpdb->prefix . \"kl_boundary\n";
echo "     WHERE event = 'rate_limit_hit'\n";
echo "       AND created_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 5 MINUTE)\n";
echo "     ORDER BY created_at DESC LIMIT 5\"\n";
echo "  ));'\n";
exit( 0 );
