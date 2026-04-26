<?php
/**
 * Bundled Cloudflare IP lists.
 *
 * Snapshot taken 2026-04-26 from
 * https://www.cloudflare.com/ips-v4 / https://www.cloudflare.com/ips-v6
 * so first install works without an internet round-trip. Refreshed
 * weekly via WP cron — see TrustedProxyResolver::refresh_cloudflare_ips().
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 *
 * @package WickedEvolutions\McpAdapter
 */

declare( strict_types=1 );

namespace WickedEvolutions\McpAdapter\RateLimit;

final class CloudflareIps {

	/**
	 * @return string[]
	 */
	public static function bundled_v4(): array {
		return array(
			'173.245.48.0/20',
			'103.21.244.0/22',
			'103.22.200.0/22',
			'103.31.4.0/22',
			'141.101.64.0/18',
			'108.162.192.0/18',
			'190.93.240.0/20',
			'188.114.96.0/20',
			'197.234.240.0/22',
			'198.41.128.0/17',
			'162.158.0.0/15',
			'104.16.0.0/13',
			'104.24.0.0/14',
			'172.64.0.0/13',
			'131.0.72.0/22',
		);
	}

	/**
	 * @return string[]
	 */
	public static function bundled_v6(): array {
		return array(
			'2400:cb00::/32',
			'2606:4700::/32',
			'2803:f800::/32',
			'2405:b500::/32',
			'2405:8100::/32',
			'2a06:98c0::/29',
			'2c0f:f248::/32',
		);
	}
}
