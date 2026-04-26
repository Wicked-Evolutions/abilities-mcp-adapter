<?php
/**
 * Trusted-proxy / client-IP resolution for the rate limiter.
 *
 * Default and only trusted source is REMOTE_ADDR. Forwarding headers
 * (X-Forwarded-For, CF-Connecting-IP, X-Real-IP, True-Client-IP) are
 * honored only when the operator explicitly enables a trusted-proxy
 * mode AND the connecting REMOTE_ADDR matches an allowlist entry or
 * a known Cloudflare edge IP.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\RateLimit;

use WickedEvolutions\McpAdapter\Settings\SafetySettingsRepository;

/**
 * Resolves the client IP that the limiter should bucket against.
 */
class TrustedProxyResolver {

	/**
	 * Legacy option key — kept for any downstream reference. Live storage
	 * is delegated to {@see SafetySettingsRepository} as of Launch Gate
	 * runbook v0.2.0; no get_option/update_option call uses this name now.
	 */
	public const OPTION_NAME = 'abilities_mcp_trusted_proxy';

	public const MODE_CLOUDFLARE  = 'cloudflare';
	public const MODE_CUSTOM_LIST = 'custom_list';

	public const TRANSIENT_CF_V4 = 'abilities_mcp_cloudflare_ips_v4';
	public const TRANSIENT_CF_V6 = 'abilities_mcp_cloudflare_ips_v6';
	public const CRON_HOOK       = 'abilities_mcp_refresh_cloudflare_ips';

	/**
	 * Cache TTL for Cloudflare IP transients (7 days).
	 */
	public const CF_TTL_SECONDS = 604800;

	/**
	 * Forwarding headers checked in order. First non-empty wins.
	 *
	 * @var string[]
	 */
	private const FORWARDING_HEADERS = array(
		'HTTP_CF_CONNECTING_IP',
		'HTTP_TRUE_CLIENT_IP',
		'HTTP_X_REAL_IP',
		'HTTP_X_FORWARDED_FOR',
	);

	/**
	 * Resolve the client IP from a $_SERVER-shaped array.
	 *
	 * @param array $server $_SERVER-style array.
	 *
	 * @return string Client IP, or '' if no usable address found.
	 */
	public static function resolve( array $server ): string {
		$remote = self::extract_remote_addr( $server );
		if ( '' === $remote ) {
			return '';
		}

		$settings = self::get_settings();
		if ( empty( $settings['enabled'] ) ) {
			return $remote;
		}

		$mode = $settings['mode'] ?? self::MODE_CLOUDFLARE;
		$is_trusted = false;
		if ( self::MODE_CUSTOM_LIST === $mode ) {
			$is_trusted = self::ip_in_cidr_list( $remote, $settings['allowlist'] ?? array() );
		} elseif ( self::MODE_CLOUDFLARE === $mode ) {
			$is_trusted = self::ip_in_cidr_list( $remote, self::get_cloudflare_ips() );
		}

		if ( ! $is_trusted ) {
			return $remote;
		}

		// REMOTE_ADDR is a known proxy — read the forwarded client IP.
		foreach ( self::FORWARDING_HEADERS as $header ) {
			if ( ! isset( $server[ $header ] ) || ! is_string( $server[ $header ] ) ) {
				continue;
			}
			$forwarded = self::first_valid_ip( $server[ $header ] );
			if ( '' !== $forwarded ) {
				return $forwarded;
			}
		}

		return $remote;
	}

	/**
	 * Truncate an IP for boundary-log tagging (PII policy).
	 *
	 * IPv4 → /24, IPv6 → /48.
	 *
	 * @param string $ip
	 * @return string Truncated IP, or '' if invalid.
	 */
	public static function truncate_for_log( string $ip ): string {
		if ( '' === $ip ) {
			return '';
		}
		$parsed = inet_pton( $ip );
		if ( false === $parsed ) {
			return '';
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			if ( 4 !== count( $parts ) ) {
				return '';
			}
			return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
		}
		// IPv6 — keep first 48 bits (3 groups).
		$expanded = self::expand_ipv6( $ip );
		if ( '' === $expanded ) {
			return '';
		}
		$groups = explode( ':', $expanded );
		return $groups[0] . ':' . $groups[1] . ':' . $groups[2] . '::/48';
	}

	/**
	 * Get current settings, with defaults applied.
	 *
	 * Reads through {@see SafetySettingsRepository} (Launch Gate runbook v0.2.0).
	 * The repository stores the three pieces (enabled / mode / allowlist) under
	 * separate option keys; this method composes them back into the array shape
	 * the limiter expects. Mode and allowlist representations are normalised at
	 * this boundary so DB-4's public API (MODE_CUSTOM_LIST, allowlist:string[])
	 * stays unchanged.
	 *
	 * @return array{enabled:bool,mode:string,allowlist:array<string>}
	 */
	public static function get_settings(): array {
		$enabled       = SafetySettingsRepository::is_trusted_proxy_enabled();
		$mode_internal = SafetySettingsRepository::get_trusted_proxy_mode();
		$allowlist_raw = SafetySettingsRepository::get_trusted_proxy_allowlist_raw();

		return array(
			'enabled'   => $enabled,
			'mode'      => SafetySettingsRepository::PROXY_MODE_CUSTOM === $mode_internal
				? self::MODE_CUSTOM_LIST
				: self::MODE_CLOUDFLARE,
			'allowlist' => self::parse_allowlist_raw( $allowlist_raw ),
		);
	}

	/**
	 * Update settings.
	 *
	 * Writes through {@see SafetySettingsRepository}. Bogus CIDR entries are
	 * still filtered here (matches the previous behaviour); the repository's
	 * own line-level sanitiser then re-checks the textarea form.
	 *
	 * @param array{enabled?:bool,mode?:string,allowlist?:array<string>} $settings
	 *
	 * @return bool True on success.
	 */
	public static function update_settings( array $settings ): bool {
		$current = self::get_settings();

		$enabled = array_key_exists( 'enabled', $settings )
			? (bool) $settings['enabled']
			: $current['enabled'];

		$mode = array_key_exists( 'mode', $settings ) && self::MODE_CUSTOM_LIST === $settings['mode']
			? self::MODE_CUSTOM_LIST
			: self::MODE_CLOUDFLARE;

		$allowlist = array_key_exists( 'allowlist', $settings ) && is_array( $settings['allowlist'] )
			? array_values( array_filter(
				array_map( 'strval', $settings['allowlist'] ),
				static fn( string $cidr ): bool => self::is_valid_cidr( $cidr )
			) )
			: $current['allowlist'];

		SafetySettingsRepository::set_trusted_proxy_enabled( $enabled );
		SafetySettingsRepository::set_trusted_proxy_mode(
			self::MODE_CUSTOM_LIST === $mode
				? SafetySettingsRepository::PROXY_MODE_CUSTOM
				: SafetySettingsRepository::PROXY_MODE_CLOUDFLARE
		);
		SafetySettingsRepository::set_trusted_proxy_allowlist_raw( implode( "\n", $allowlist ) );

		return true;
	}

	/**
	 * Parse the repository's newline-delimited allowlist string into a
	 * `string[]` of valid CIDRs / IPs. Lines that don't validate are dropped.
	 *
	 * @param string $raw
	 * @return string[]
	 */
	private static function parse_allowlist_raw( string $raw ): array {
		if ( '' === $raw ) {
			return array();
		}
		$out = array();
		foreach ( preg_split( '/\r\n|\r|\n/', $raw ) ?: array() as $line ) {
			$line = trim( (string) $line );
			if ( '' === $line || str_starts_with( $line, '#' ) ) {
				continue;
			}
			if ( self::is_valid_cidr( $line ) ) {
				$out[] = $line;
			}
		}
		return $out;
	}

	/**
	 * Get the list of Cloudflare CIDRs (v4 + v6), pulling from cache,
	 * falling back to the bundled list.
	 *
	 * @return string[]
	 */
	public static function get_cloudflare_ips(): array {
		$v4 = function_exists( 'get_transient' ) ? get_transient( self::TRANSIENT_CF_V4 ) : false;
		$v6 = function_exists( 'get_transient' ) ? get_transient( self::TRANSIENT_CF_V6 ) : false;

		if ( ! is_array( $v4 ) || empty( $v4 ) ) {
			$v4 = CloudflareIps::bundled_v4();
			if ( function_exists( 'set_transient' ) ) {
				set_transient( self::TRANSIENT_CF_V4, $v4, self::CF_TTL_SECONDS );
			}
		}
		if ( ! is_array( $v6 ) || empty( $v6 ) ) {
			$v6 = CloudflareIps::bundled_v6();
			if ( function_exists( 'set_transient' ) ) {
				set_transient( self::TRANSIENT_CF_V6, $v6, self::CF_TTL_SECONDS );
			}
		}

		return array_merge( $v4, $v6 );
	}

	/**
	 * Refresh the Cloudflare IP cache from cloudflare.com.
	 * On fetch failure, keeps the existing cache (stale-while-failing).
	 *
	 * @return void
	 */
	public static function refresh_cloudflare_ips(): void {
		$v4 = self::fetch_cf_list( 'https://www.cloudflare.com/ips-v4' );
		$v6 = self::fetch_cf_list( 'https://www.cloudflare.com/ips-v6' );

		if ( ! empty( $v4 ) && function_exists( 'set_transient' ) ) {
			set_transient( self::TRANSIENT_CF_V4, $v4, self::CF_TTL_SECONDS );
		}
		if ( ! empty( $v6 ) && function_exists( 'set_transient' ) ) {
			set_transient( self::TRANSIENT_CF_V6, $v6, self::CF_TTL_SECONDS );
		}
	}

	/**
	 * Whether an IP belongs to one of the given CIDR ranges.
	 *
	 * @param string   $ip
	 * @param string[] $cidrs
	 * @return bool
	 */
	public static function ip_in_cidr_list( string $ip, array $cidrs ): bool {
		foreach ( $cidrs as $cidr ) {
			if ( ! is_string( $cidr ) ) {
				continue;
			}
			if ( self::ip_in_cidr( $ip, $cidr ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Single-CIDR membership check (handles bare IPs and v4/v6).
	 *
	 * @param string $ip
	 * @param string $cidr
	 * @return bool
	 */
	public static function ip_in_cidr( string $ip, string $cidr ): bool {
		$cidr = trim( $cidr );
		if ( '' === $cidr ) {
			return false;
		}

		if ( strpos( $cidr, '/' ) === false ) {
			return $ip === $cidr;
		}

		[ $subnet, $bits ] = explode( '/', $cidr, 2 );
		$bits              = (int) $bits;

		$ip_bin     = @inet_pton( $ip );
		$subnet_bin = @inet_pton( $subnet );
		if ( false === $ip_bin || false === $subnet_bin ) {
			return false;
		}
		if ( strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false; // Mismatched address families.
		}

		$bytes_full = intdiv( $bits, 8 );
		$bits_rem   = $bits % 8;

		if ( $bytes_full > 0 && substr( $ip_bin, 0, $bytes_full ) !== substr( $subnet_bin, 0, $bytes_full ) ) {
			return false;
		}
		if ( 0 === $bits_rem ) {
			return true;
		}

		$mask = chr( ( 0xff << ( 8 - $bits_rem ) ) & 0xff );
		return ( $ip_bin[ $bytes_full ] & $mask ) === ( $subnet_bin[ $bytes_full ] & $mask );
	}

	/**
	 * @param string $cidr
	 * @return bool
	 */
	public static function is_valid_cidr( string $cidr ): bool {
		$cidr = trim( $cidr );
		if ( '' === $cidr ) {
			return false;
		}
		if ( strpos( $cidr, '/' ) === false ) {
			return false !== filter_var( $cidr, FILTER_VALIDATE_IP );
		}
		[ $subnet, $bits ] = explode( '/', $cidr, 2 );
		if ( ! ctype_digit( $bits ) ) {
			return false;
		}
		$bits_int = (int) $bits;
		if ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return $bits_int >= 0 && $bits_int <= 32;
		}
		if ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return $bits_int >= 0 && $bits_int <= 128;
		}
		return false;
	}

	/**
	 * @param array $server
	 * @return string
	 */
	private static function extract_remote_addr( array $server ): string {
		if ( ! isset( $server['REMOTE_ADDR'] ) || ! is_string( $server['REMOTE_ADDR'] ) ) {
			return '';
		}
		$ip = trim( $server['REMOTE_ADDR'] );
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		return $ip;
	}

	/**
	 * Pick the first syntactically valid IP from a (possibly comma-separated)
	 * forwarded-header value.
	 *
	 * @param string $value
	 * @return string
	 */
	private static function first_valid_ip( string $value ): string {
		foreach ( explode( ',', $value ) as $candidate ) {
			$candidate = trim( $candidate );
			if ( '' === $candidate ) {
				continue;
			}
			if ( false !== filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				return $candidate;
			}
		}
		return '';
	}

	/**
	 * Expand a compressed IPv6 address to its full eight-group form.
	 *
	 * @param string $ip
	 * @return string '' on failure.
	 */
	private static function expand_ipv6( string $ip ): string {
		$bin = @inet_pton( $ip );
		if ( false === $bin || strlen( $bin ) !== 16 ) {
			return '';
		}
		$hex   = bin2hex( $bin );
		$parts = str_split( $hex, 4 );
		return implode( ':', $parts );
	}

	/**
	 * @param string $url
	 * @return string[]
	 */
	private static function fetch_cf_list( string $url ): array {
		if ( ! function_exists( 'wp_remote_get' ) || ! function_exists( 'wp_remote_retrieve_body' ) ) {
			return array();
		}
		$response = wp_remote_get( $url, array( 'timeout' => 5 ) );
		if ( function_exists( 'is_wp_error' ) && is_wp_error( $response ) ) {
			return array();
		}
		$body = wp_remote_retrieve_body( $response );
		if ( ! is_string( $body ) || '' === $body ) {
			return array();
		}
		$lines = preg_split( '/\r\n|\r|\n/', $body );
		$out   = array();
		foreach ( (array) $lines as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			if ( self::is_valid_cidr( $line ) ) {
				$out[] = $line;
			}
		}
		return $out;
	}
}
