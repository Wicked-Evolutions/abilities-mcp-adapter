<?php
/**
 * Plugin Updater — FluentCart License API Integration
 *
 * Checks for plugin updates via the FluentCart `get_license_version` endpoint
 * and integrates with WordPress's native plugin update system.
 *
 * Based on FluentCart Pro's PluginUpdater pattern (GPL-2.0-or-later).
 * Adapted for Wicked Evolutions product distribution.
 *
 * @package Abilities_MCP_Adapter
 */

defined( 'ABSPATH' ) || exit;

class Abilities_MCP_Adapter_Plugin_Updater {

	/**
	 * Transient cache key for version info.
	 *
	 * @var string
	 */
	private $cache_key;

	/**
	 * Updater configuration.
	 *
	 * @var array
	 */
	private $config = array();

	/**
	 * Initialize the updater.
	 *
	 * @param array $config {
	 *     @type string $slug     Plugin slug (e.g. 'abilities-for-ai').
	 *     @type string $basename Plugin basename (e.g. 'abilities-for-ai/abilities-for-ai.php').
	 *     @type string $version  Current plugin version.
	 *     @type int    $item_id  FluentCart product ID.
	 *     @type string $api_url  FluentCart store URL.
	 *     @type string $license_key          Optional license key.
	 *     @type callable $license_key_callback Optional callback to retrieve license key.
	 *     @type bool   $show_check_update     Show "Check Update" link in plugin row.
	 * }
	 */
	public function __construct( $config = array() ) {
		$defaults = array(
			'slug'                 => '',
			'basename'             => '',
			'version'              => '',
			'item_id'              => '',
			'api_url'              => '',
			'license_key'          => '',
			'license_key_callback' => '',
			'github_repo'          => '',
			'show_check_update'    => true,
		);

		$this->config    = wp_parse_args( $config, $defaults );
		$this->cache_key = 'wevo_' . md5( $this->config['basename'] . '_' . $this->config['item_id'] ) . '_version_info';

		$this->init_hooks();
	}

	/**
	 * Register WordPress hooks for update checking.
	 */
	private function init_hooks() {
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_plugin_update' ) );
		add_filter( 'plugins_api', array( $this, 'plugins_api_filter' ), 10, 3 );
		add_filter( 'upgrader_pre_download', array( $this, 'pre_download' ), 10, 3 );

		if ( $this->config['show_check_update'] ) {
			$get_param = 'wevo_check_update_' . $this->config['slug'];

			add_filter( 'plugin_row_meta', function( $links, $file ) use ( $get_param ) {
				if ( $this->config['basename'] !== $file ) {
					return $links;
				}

				$check_url = esc_url( admin_url( 'plugins.php?' . $get_param . '=' . time() ) );
				$links['check_update'] = '<a style="color: #583fad; font-weight: 600;" href="' . $check_url . '">Check Update</a>';

				return $links;
			}, 10, 2 );

			if ( isset( $_GET[ $get_param ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
				add_action( 'admin_init', function() {
					if ( ! current_user_can( 'update_plugins' ) ) {
						return;
					}

					delete_site_transient( $this->cache_key );

					// Disable API-side cache for this request.
					add_filter( 'fluent_sl/api_request_query_params', function( $params ) {
						$params['disable_cache'] = 'yes';
						return $params;
					} );

					remove_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_plugin_update' ) );

					$update_cache = get_site_transient( 'update_plugins' );
					if ( $update_cache && ! empty( $update_cache->response[ $this->config['basename'] ] ) ) {
						unset( $update_cache->response[ $this->config['basename'] ] );
					}

					$update_cache = $this->check_plugin_update( $update_cache );
					set_site_transient( 'update_plugins', $update_cache );

					add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_plugin_update' ) );

					wp_safe_redirect( admin_url( 'plugins.php?s=' . $this->config['slug'] . '&plugin_status=all' ) );
					exit();
				} );
			}
		}
	}

	/**
	 * Check for plugin updates.
	 *
	 * Hooked into `pre_set_site_transient_update_plugins`.
	 *
	 * @param object $transient_data Update transient data.
	 * @return object Modified transient data.
	 */
	public function check_plugin_update( $transient_data ) {
		global $pagenow;

		if ( ! is_object( $transient_data ) ) {
			$transient_data = new stdClass();
		}

		if ( ! empty( $transient_data->response ) && ! empty( $transient_data->response[ $this->config['basename'] ] ) ) {
			return $transient_data;
		}

		$version_info = $this->get_version_info();

		if ( false !== $version_info && is_object( $version_info ) && isset( $version_info->new_version ) ) {
			unset( $version_info->sections );

			if ( version_compare( $this->config['version'], $version_info->new_version, '<' ) ) {
				$transient_data->response[ $this->config['basename'] ] = $version_info;
			} else {
				$transient_data->no_update[ $this->config['basename'] ] = $version_info;
			}

			$transient_data->last_checked                          = time();
			$transient_data->checked[ $this->config['basename'] ] = $this->config['version'];
		}

		return $transient_data;
	}

	/**
	 * Filter the plugins_api response for this plugin.
	 *
	 * Provides the "View Details" modal content in WP Admin.
	 *
	 * @param mixed  $data   Plugin data.
	 * @param string $action API action.
	 * @param object $args   Request arguments.
	 * @return mixed
	 */
	public function plugins_api_filter( $data, $action = '', $args = null ) {
		if ( 'plugin_information' !== $action || ! $args ) {
			return $data;
		}

		if ( ! isset( $args->slug ) || $args->slug !== $this->config['slug'] ) {
			return $data;
		}

		$data = $this->get_version_info();

		if ( is_wp_error( $data ) ) {
			return $data;
		}

		if ( ! $data ) {
			return new WP_Error( 'no_data', 'No update data found for this plugin.' );
		}

		return $data;
	}

	/**
	 * Pre-download the package before WordPress enables maintenance mode.
	 *
	 * When the update server is hosted on the same WordPress installation,
	 * maintenance mode returns HTTP 503 to the download request. This hook
	 * fires before maintenance mode, so the download succeeds.
	 *
	 * @param bool|WP_Error $reply   Whether to short-circuit. Default false.
	 * @param string        $package The package URL.
	 * @param WP_Upgrader   $upgrader The upgrader instance.
	 * @return string|bool|WP_Error Local path to the downloaded file, or passthrough.
	 */
	public function pre_download( $reply, $package, $upgrader ) {
		if ( false !== $reply ) {
			return $reply;
		}

		if ( empty( $this->config['api_url'] ) || empty( $package ) ) {
			return $reply;
		}

		// Only handle downloads from our own update server.
		if ( strpos( $package, wp_parse_url( $this->config['api_url'], PHP_URL_HOST ) ) === false ) {
			return $reply;
		}

		$tmpfile = download_url( $package, 300 );

		if ( is_wp_error( $tmpfile ) ) {
			return $tmpfile;
		}

		return $tmpfile;
	}

	/**
	 * Get version info, using transient cache.
	 *
	 * @return object|false Version info or false on failure.
	 */
	private function get_version_info() {
		$cached = $this->get_cached_version_info();

		if ( false === $cached ) {
			$cached = $this->get_remote_version_info();
			$this->set_cached_version_info( $cached );
		}

		return $cached;
	}

	/**
	 * Read cached version info from transient.
	 *
	 * Forces a fresh fetch on update-core.php and plugin-install.php.
	 *
	 * @return object|false
	 */
	private function get_cached_version_info() {
		global $pagenow;

		if ( 'update-core.php' === $pagenow || ( 'plugin-install.php' === $pagenow && ! empty( $_GET['plugin'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return false;
		}

		return get_site_transient( $this->cache_key );
	}

	/**
	 * Store version info in transient (3-hour TTL).
	 *
	 * @param object|false $value Version info.
	 */
	private function set_cached_version_info( $value ) {
		if ( ! $value ) {
			return;
		}

		set_site_transient( $this->cache_key, $value, 3 * HOUR_IN_SECONDS );
	}

	/**
	 * Fetch version info from FluentCart, falling back to GitHub Releases.
	 *
	 * @return object|false Version info object or false on failure.
	 */
	private function get_remote_version_info() {
		// Try FluentCart first (requires license for download URL).
		$version_info = $this->get_fluentcart_version_info();

		// Fall back to GitHub Releases if FluentCart fails or has no license.
		if ( false === $version_info && ! empty( $this->config['github_repo'] ) ) {
			$version_info = $this->get_github_version_info();
		}

		return $version_info;
	}

	/**
	 * Fetch version info from the FluentCart `get_license_version` endpoint.
	 *
	 * @return object|false Version info object or false on failure.
	 */
	private function get_fluentcart_version_info() {
		if ( empty( $this->config['api_url'] ) || empty( $this->config['item_id'] ) ) {
			return false;
		}

		$url = add_query_arg(
			apply_filters( 'fluent_sl/api_request_query_params', array(
				'fluent-cart' => 'get_license_version',
			), $this->config ),
			$this->config['api_url'] . '/'
		);

		$license_key = $this->config['license_key'];
		if ( empty( $license_key ) && ! empty( $this->config['license_key_callback'] ) ) {
			$license_key = call_user_func( $this->config['license_key_callback'] );
		}

		$payload = array(
			'item_id'          => $this->config['item_id'],
			'current_version'  => $this->config['version'],
			'site_url'         => home_url(),
			'platform_version' => get_bloginfo( 'version' ),
			'server_version'   => PHP_VERSION,
			'license_key'      => $license_key,
		);

		$response = wp_remote_post( $url, array(
			'timeout'   => 15,
			'sslverify' => true,
			'body'      => $payload,
		) );

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		if ( empty( $body ) ) {
			return false;
		}

		$version_info = json_decode( $body );
		if ( null === $version_info || ! is_object( $version_info ) || ! isset( $version_info->new_version ) ) {
			return false;
		}

		return $this->normalize_version_info( $version_info );
	}

	/**
	 * Fetch version info from GitHub Releases API.
	 *
	 * Uses the public GitHub API (no auth required for public repos).
	 * Falls back here when FluentCart fails — ensures users who installed
	 * from GitHub still get update notifications.
	 *
	 * @return object|false Version info object or false on failure.
	 */
	private function get_github_version_info() {
		$repo = $this->config['github_repo']; // e.g. 'Wicked-Evolutions/abilities-mcp-adapter'

		$response = wp_remote_get( "https://api.github.com/repos/{$repo}/releases/latest", array(
			'timeout'   => 15,
			'sslverify' => true,
			'headers'   => array(
				'Accept'     => 'application/vnd.github.v3+json',
				'User-Agent' => 'WordPress/' . get_bloginfo( 'version' ) . '; ' . home_url(),
			),
		) );

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$release = json_decode( wp_remote_retrieve_body( $response ) );
		if ( ! $release || ! isset( $release->tag_name ) ) {
			return false;
		}

		// Strip 'v' prefix from tag (v1.1.0 → 1.1.0).
		$new_version = ltrim( $release->tag_name, 'v' );

		// Find the zip asset attached to the release.
		$download_url = '';
		if ( ! empty( $release->assets ) ) {
			foreach ( $release->assets as $asset ) {
				if ( substr( $asset->name, -4 ) === '.zip' ) {
					$download_url = $asset->browser_download_url;
					break;
				}
			}
		}

		if ( empty( $download_url ) ) {
			return false;
		}

		$version_info = (object) array(
			'new_version' => $new_version,
			'package'     => $download_url,
			'url'         => "https://github.com/{$repo}/releases/tag/{$release->tag_name}",
			'sections'    => array(
				'changelog'   => ! empty( $release->body ) ? $release->body : '',
				'description' => $this->config['slug'] . ' update from GitHub.',
			),
		);

		return $this->normalize_version_info( $version_info );
	}

	/**
	 * Add standard WordPress update fields to version info.
	 *
	 * @param object $version_info Raw version info.
	 * @return object Normalized version info.
	 */
	private function normalize_version_info( $version_info ) {
		$version_info->plugin = $this->config['basename'];
		$version_info->slug   = $this->config['slug'];

		if ( ! empty( $version_info->sections ) ) {
			$version_info->sections = (array) $version_info->sections;
		}

		if ( ! isset( $version_info->banners ) ) {
			$version_info->banners = array();
		} else {
			$version_info->banners = (array) $version_info->banners;
		}

		if ( ! isset( $version_info->icons ) ) {
			$version_info->icons = array();
		} else {
			$version_info->icons = (array) $version_info->icons;
		}

		return $version_info;
	}
}
