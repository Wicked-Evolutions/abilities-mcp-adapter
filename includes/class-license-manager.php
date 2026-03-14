<?php
/**
 * License Manager — FluentCart API Integration
 *
 * Validates Abilities MCP Adapter licenses via the FluentCart license API.
 * Uses a 24-hour transient cache and a 7-day grace period.
 *
 * Adapted from Abilities for AI license-manager.php for the free
 * MCP Adapter plugin. License is used for auto-update delivery only.
 *
 * Copyright (C) 2026 Influencentricity | Wicked Evolutions
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package Abilities_MCP_Adapter
 */

defined( 'ABSPATH' ) || exit;

class Abilities_MCP_Adapter_License_Manager {

	/**
	 * FluentCart store URL.
	 *
	 * @var string
	 */
	const STORE_URL = 'https://community.wickedevolutions.com';

	/**
	 * Cache lifetime for a successful validation result (24 hours).
	 *
	 * @var int
	 */
	const CACHE_TTL = DAY_IN_SECONDS;

	/**
	 * Grace period when the license API is unreachable (7 days).
	 *
	 * @var int
	 */
	const GRACE_PERIOD = 7 * DAY_IN_SECONDS;

	/**
	 * FluentCart product ID for Abilities MCP Adapter.
	 *
	 * @var int
	 */
	const PRODUCT_ID = 82;

	// WordPress option / transient keys.
	const OPT_LICENSE_KEY  = 'abilities_mcp_adapter_license_key';
	const OPT_ACTIV_HASH   = 'abilities_mcp_adapter_activation_hash';
	const OPT_LAST_VALID   = 'abilities_mcp_adapter_last_valid_ts';
	const OPT_PRODUCT_ID   = 'abilities_mcp_adapter_product_id';
	const TRANSIENT_STATUS = 'abilities_mcp_adapter_license_status';

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	/**
	 * Get the current license key.
	 *
	 * @return string License key or empty string.
	 */
	public static function get_license_key() {
		return self::get_opt( self::OPT_LICENSE_KEY, '' );
	}

	/**
	 * Get the FluentCart product ID.
	 *
	 * @return int
	 */
	public static function get_product_id() {
		$stored = (int) self::get_opt( self::OPT_PRODUCT_ID, 0 );
		return $stored ?: self::PRODUCT_ID;
	}

	/**
	 * Check if a license is currently active.
	 *
	 * @return bool
	 */
	public static function is_active() {
		$cached = get_transient( self::TRANSIENT_STATUS );
		if ( false !== $cached ) {
			return 'active' === $cached;
		}

		$license_key = self::get_opt( self::OPT_LICENSE_KEY, '' );
		if ( empty( $license_key ) ) {
			return false;
		}

		$result = self::remote_check( $license_key );

		if ( is_wp_error( $result ) ) {
			return self::is_within_grace_period();
		}

		$is_active = isset( $result['status'] ) && 'valid' === $result['status'];

		if ( $is_active ) {
			self::update_opt( self::OPT_LAST_VALID, time() );
			set_transient( self::TRANSIENT_STATUS, 'active', self::CACHE_TTL );
		} else {
			set_transient( self::TRANSIENT_STATUS, 'inactive', self::CACHE_TTL );
		}

		return $is_active;
	}

	/**
	 * Activate a license key.
	 *
	 * @param string $license_key The license key to activate.
	 * @return true|WP_Error
	 */
	public static function activate( $license_key ) {
		$license_key = sanitize_text_field( $license_key );
		if ( empty( $license_key ) ) {
			return new WP_Error( 'invalid_key', __( 'License key cannot be empty.', 'abilities-mcp-adapter' ) );
		}

		$product_id = self::get_product_id();

		$response = self::remote_request( 'activate_license', array(
			'license_key' => $license_key,
			'item_id'     => $product_id,
			'site_url'    => home_url(),
		) );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( ! isset( $response['status'] ) || 'valid' !== $response['status'] ) {
			$message = $response['message'] ?? __( 'License activation failed.', 'abilities-mcp-adapter' );
			return new WP_Error( $response['error_type'] ?? 'activation_failed', $message );
		}

		// Store the product_id from the API response.
		$response_product = (int) ( $response['product_id'] ?? $product_id );
		self::update_opt( self::OPT_PRODUCT_ID, $response_product );

		// Detect multisite license scope from variation title.
		$variation_title = $response['variation_title'] ?? '';
		$is_network      = is_multisite() && stripos( $variation_title, 'multi site' ) !== false;

		if ( $is_network ) {
			update_site_option( 'abilities_mcp_adapter_license_scope', 'network' );
		} else {
			delete_site_option( 'abilities_mcp_adapter_license_scope' );
		}

		// Store the key and activation hash.
		self::update_opt( self::OPT_LICENSE_KEY, $license_key );
		self::update_opt( self::OPT_ACTIV_HASH, $response['activation_hash'] ?? '' );
		self::update_opt( self::OPT_LAST_VALID, time() );

		delete_transient( self::TRANSIENT_STATUS );

		return true;
	}

	/**
	 * Deactivate the current license.
	 *
	 * @return bool
	 */
	public static function deactivate() {
		$license_key = self::get_opt( self::OPT_LICENSE_KEY, '' );
		$activ_hash  = self::get_opt( self::OPT_ACTIV_HASH, '' );
		$product_id  = self::get_product_id();

		if ( ! empty( $license_key ) && $product_id ) {
			self::remote_request( 'deactivate_license', array(
				'license_key'     => $license_key,
				'activation_hash' => $activ_hash,
				'item_id'         => $product_id,
				'site_url'        => home_url(),
			) );
		}

		self::delete_opt( self::OPT_LICENSE_KEY );
		self::delete_opt( self::OPT_ACTIV_HASH );
		self::delete_opt( self::OPT_LAST_VALID );
		self::delete_opt( self::OPT_PRODUCT_ID );
		delete_transient( self::TRANSIENT_STATUS );
		delete_site_option( 'abilities_mcp_adapter_license_scope' );

		return true;
	}

	/**
	 * Get the current license status details for admin UI.
	 *
	 * @return array Keys: key (masked), status, product_id, activated, last_valid.
	 */
	public static function get_status() {
		$license_key = self::get_opt( self::OPT_LICENSE_KEY, '' );
		$last_valid  = self::get_opt( self::OPT_LAST_VALID, 0 );

		if ( empty( $license_key ) ) {
			return array(
				'key'        => '',
				'status'     => 'unlicensed',
				'product_id' => self::get_product_id(),
				'activated'  => false,
				'last_valid' => '',
			);
		}

		// Mask the key for display.
		$masked_key = substr( $license_key, 0, 6 ) . str_repeat( '*', max( 0, strlen( $license_key ) - 9 ) ) . substr( $license_key, -3 );

		$is_active = self::is_active();

		return array(
			'key'        => $masked_key,
			'status'     => $is_active ? 'active' : 'inactive',
			'product_id' => self::get_product_id(),
			'activated'  => $is_active,
			'last_valid' => $last_valid ? gmdate( 'Y-m-d H:i:s', $last_valid ) : '',
		);
	}

	// -------------------------------------------------------------------------
	// Internal Helpers
	// -------------------------------------------------------------------------

	/**
	 * Whether the current license has network (multisite) scope.
	 *
	 * @return bool
	 */
	private static function is_network_license() {
		if ( ! is_multisite() ) {
			return false;
		}
		return 'network' === get_site_option( 'abilities_mcp_adapter_license_scope', '' );
	}

	/**
	 * Read a license option, respecting network scope.
	 *
	 * @param string $key     Option key.
	 * @param mixed  $default Default value.
	 * @return mixed
	 */
	private static function get_opt( $key, $default = '' ) {
		return self::is_network_license() ? get_site_option( $key, $default ) : get_option( $key, $default );
	}

	/**
	 * Write a license option, respecting network scope.
	 *
	 * @param string $key   Option key.
	 * @param mixed  $value Value.
	 */
	private static function update_opt( $key, $value ) {
		if ( self::is_network_license() ) {
			update_site_option( $key, $value );
		} else {
			update_option( $key, $value );
		}
	}

	/**
	 * Delete a license option, respecting network scope.
	 *
	 * @param string $key Option key.
	 */
	private static function delete_opt( $key ) {
		if ( self::is_network_license() ) {
			delete_site_option( $key );
		} else {
			delete_option( $key );
		}
	}

	/**
	 * POST to the FluentCart check_license endpoint.
	 *
	 * @param string $license_key License key.
	 * @return array|WP_Error Decoded JSON response or WP_Error.
	 */
	private static function remote_check( $license_key ) {
		$activ_hash = self::get_opt( self::OPT_ACTIV_HASH, '' );
		$product_id = self::get_product_id();

		if ( ! $product_id ) {
			return new WP_Error( 'no_product_id', 'No product ID stored. Re-activate your license.' );
		}

		$payload = array(
			'item_id'  => $product_id,
			'site_url' => home_url(),
		);

		if ( ! empty( $activ_hash ) ) {
			$payload['activation_hash'] = $activ_hash;
		} else {
			$payload['license_key'] = $license_key;
		}

		return self::remote_request( 'check_license', $payload );
	}

	/**
	 * POST to the FluentCart license API.
	 *
	 * @param string $action  One of: activate_license, check_license, deactivate_license.
	 * @param array  $payload POST body fields.
	 * @return array|WP_Error Decoded JSON response or WP_Error.
	 */
	private static function remote_request( $action, array $payload ) {
		$url = add_query_arg( 'fluent-cart', $action, self::STORE_URL . '/' );

		$response = wp_remote_post( $url, array(
			'timeout'   => 15,
			'sslverify' => true,
			'body'      => $payload,
		) );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		$decoded = json_decode( $body, true );

		if ( ! is_array( $decoded ) ) {
			return new WP_Error(
				'invalid_response',
				sprintf( 'License API returned unexpected response (HTTP %d).', $code )
			);
		}

		return $decoded;
	}

	/**
	 * Check whether the last known-valid timestamp is within the grace period.
	 *
	 * @return bool
	 */
	private static function is_within_grace_period() {
		$last_valid = (int) self::get_opt( self::OPT_LAST_VALID, 0 );
		if ( $last_valid <= 0 ) {
			return false;
		}
		return ( time() - $last_valid ) < self::GRACE_PERIOD;
	}
}
