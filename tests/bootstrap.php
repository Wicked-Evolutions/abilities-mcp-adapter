<?php
/**
 * PHPUnit bootstrap for MCP Adapter unit tests.
 *
 * Provides minimal WordPress function stubs so unit tests can run
 * without a full WordPress installation.
 */

// Composer autoloader.
require_once dirname( __DIR__ ) . '/vendor/autoload.php';

// WordPress function stubs — only what the P0 test targets need.

if ( ! function_exists( '__' ) ) {
	function __( $text, $domain = 'default' ) {
		return $text;
	}
}

if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_html__' ) ) {
	function esc_html__( $text, $domain = 'default' ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	function is_wp_error( $thing ) {
		return $thing instanceof WP_Error;
	}
}

// Simple in-memory option store for testing.
if ( ! isset( $GLOBALS['wp_test_options'] ) ) {
	$GLOBALS['wp_test_options'] = array();
}

if ( ! function_exists( 'get_option' ) ) {
	function get_option( $option, $default = false ) {
		return $GLOBALS['wp_test_options'][ $option ] ?? $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	function update_option( $option, $value, $autoload = null ) {
		$GLOBALS['wp_test_options'][ $option ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_option' ) ) {
	function delete_option( $option ) {
		unset( $GLOBALS['wp_test_options'][ $option ] );
		return true;
	}
}

// Transients (DB-3's TTL-aware shape — DB-4's no-TTL variant was dropped
// in integration; tests that don't care about TTL still get correct values).
if ( ! isset( $GLOBALS['wp_test_transients'] ) ) {
	$GLOBALS['wp_test_transients'] = array();
}

if ( ! function_exists( 'set_transient' ) ) {
	function set_transient( $key, $value, $ttl = 0 ) {
		$GLOBALS['wp_test_transients'][ $key ] = array(
			'value'   => $value,
			'expires' => time() + (int) $ttl,
		);
		return true;
	}
}

if ( ! function_exists( 'get_transient' ) ) {
	function get_transient( $key ) {
		$entry = $GLOBALS['wp_test_transients'][ $key ] ?? null;
		if ( ! $entry ) {
			return false;
		}
		if ( $entry['expires'] < time() ) {
			unset( $GLOBALS['wp_test_transients'][ $key ] );
			return false;
		}
		return $entry['value'];
	}
}

if ( ! function_exists( 'delete_transient' ) ) {
	function delete_transient( $key ) {
		unset( $GLOBALS['wp_test_transients'][ $key ] );
		return true;
	}
}

if ( ! function_exists( 'wp_generate_password' ) ) {
	function wp_generate_password( $length = 12, $special_chars = true, $extra_special_chars = false ) {
		return bin2hex( random_bytes( max( 1, (int) ( $length / 2 ) ) ) );
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data ) {
		return json_encode( $data );
	}
}

if ( ! function_exists( 'get_current_user_id' ) ) {
	function get_current_user_id() {
		return $GLOBALS['wp_test_current_user'] ?? ( $GLOBALS['wp_test_user_id'] ?? 0 );
	}
}

if ( ! function_exists( 'get_current_blog_id' ) ) {
	function get_current_blog_id() {
		return $GLOBALS['wp_test_blog_id'] ?? 1;
	}
}

if ( ! function_exists( 'sanitize_key' ) ) {
	function sanitize_key( $key ) {
		$key = strtolower( (string) $key );
		return preg_replace( '/[^a-z0-9_]/', '', $key ) ?? '';
	}
}

if ( ! function_exists( 'is_user_logged_in' ) ) {
	function is_user_logged_in() {
		return ! empty( $GLOBALS['wp_test_current_user'] );
	}
}

if ( ! function_exists( 'current_user_can' ) ) {
	function current_user_can( $capability ) {
		return ! empty( $GLOBALS['wp_test_caps'][ $capability ] );
	}
}

// Filter / action stubs.
//
// Polymorphic on `$GLOBALS['wp_test_filters'][ $hook ]`:
//   - DB-5 / direct-injection style: tests assign a single callable directly,
//     e.g. `$GLOBALS['wp_test_filters']['hook'] = fn(...) => ...;`
//   - DB-4 / registry style: tests register via `add_filter()`, which appends
//     entry arrays of shape `array('cb' => $cb, 'args' => $n, 'pri' => $p)`.
//
// `apply_filters` detects which shape is present and dispatches accordingly.
// Both styles coexist so neither side's tests had to change to integrate.
if ( ! isset( $GLOBALS['wp_test_filters'] ) ) {
	$GLOBALS['wp_test_filters'] = array();
}

if ( ! function_exists( 'apply_filters' ) ) {
	function apply_filters( $hook, $value ) {
		$args   = func_get_args();
		$value  = $args[1] ?? null;
		$extras = array_slice( $args, 2 );

		if ( ! isset( $GLOBALS['wp_test_filters'][ $hook ] ) ) {
			return $value;
		}

		$registered = $GLOBALS['wp_test_filters'][ $hook ];

		// Direct-injection style: a single callable is the registered value.
		if ( is_callable( $registered ) && ! is_array( $registered ) ) {
			$call_args = array_merge( array( $value ), $extras );
			return call_user_func_array( $registered, $call_args );
		}

		// Registry style: array of entry arrays from add_filter().
		if ( is_array( $registered ) ) {
			foreach ( $registered as $entry ) {
				if ( ! is_array( $entry ) || ! isset( $entry['cb'] ) ) {
					continue;
				}
				$accepted  = (int) ( $entry['args'] ?? 1 );
				$call_args = array_merge( array( $value ), $extras );
				$call_args = array_slice( $call_args, 0, max( 1, $accepted ) );
				$value     = call_user_func_array( $entry['cb'], $call_args );
			}
		}

		return $value;
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( $hook, $callable, $priority = 10, $accepted_args = 1 ) {
		// If a direct-injection callable is already in place for this hook,
		// don't clobber it — the test set it deliberately. Tests that mix
		// styles per hook would already be ambiguous.
		if ( isset( $GLOBALS['wp_test_filters'][ $hook ] )
			&& is_callable( $GLOBALS['wp_test_filters'][ $hook ] )
			&& ! is_array( $GLOBALS['wp_test_filters'][ $hook ] )
		) {
			return true;
		}
		if ( ! isset( $GLOBALS['wp_test_filters'][ $hook ] ) || ! is_array( $GLOBALS['wp_test_filters'][ $hook ] ) ) {
			$GLOBALS['wp_test_filters'][ $hook ] = array();
		}
		$GLOBALS['wp_test_filters'][ $hook ][] = array(
			'cb'   => $callable,
			'args' => (int) $accepted_args,
			'pri'  => (int) $priority,
		);
		return true;
	}
}

if ( ! function_exists( 'remove_all_filters' ) ) {
	function remove_all_filters( $hook = null ) {
		if ( null === $hook ) {
			$GLOBALS['wp_test_filters'] = array();
			return true;
		}
		unset( $GLOBALS['wp_test_filters'][ $hook ] );
		return true;
	}
}

if ( ! function_exists( 'do_action' ) ) {
	function do_action( $hook, ...$args ) {
		// Capture into a global buffer so tests can assert action emissions
		// without standing up a full filter pipeline. Tests opt in by reading
		// $GLOBALS['wp_test_actions_invoked']; the array is cleared per-test.
		if ( ! isset( $GLOBALS['wp_test_actions_invoked'] ) ) {
			$GLOBALS['wp_test_actions_invoked'] = array();
		}
		$GLOBALS['wp_test_actions_invoked'][] = array(
			'hook' => $hook,
			'args' => $args,
		);
		return null;
	}
}

if ( ! function_exists( 'add_action' ) ) {
	function add_action( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
		// Record so tests can assert specific (hook, callback, priority) wiring.
		if ( ! isset( $GLOBALS['wp_test_actions'] ) ) {
			$GLOBALS['wp_test_actions'] = array();
		}
		$GLOBALS['wp_test_actions'][] = array(
			'hook'     => $hook,
			'callback' => $callback,
			'priority' => $priority,
		);
		return true;
	}
}

// In-memory ability registry for tests that need to exercise
// `wp_get_abilities()` (e.g. ResponseRedactionGate's tool-name → ability-name
// translator). The real Abilities API isn't loaded here.
if ( ! isset( $GLOBALS['wp_test_abilities'] ) ) {
	$GLOBALS['wp_test_abilities'] = array();
}

if ( ! function_exists( 'wp_register_ability' ) ) {
	function wp_register_ability( $name, $args = array() ) {
		$ability = new \WP_Ability( $name, $args );
		$GLOBALS['wp_test_abilities'][ $name ] = $ability;
		return $ability;
	}
}

if ( ! function_exists( 'wp_get_ability' ) ) {
	function wp_get_ability( $name ) {
		return $GLOBALS['wp_test_abilities'][ $name ] ?? null;
	}
}

if ( ! function_exists( 'wp_get_abilities' ) ) {
	function wp_get_abilities() {
		return $GLOBALS['wp_test_abilities'];
	}
}

if ( ! function_exists( 'home_url' ) ) {
	function home_url( $path = '', $scheme = null ) {
		return ( $GLOBALS['wp_test_home_url'] ?? 'https://example.com' ) . $path;
	}
}

if ( ! function_exists( 'site_url' ) ) {
	function site_url( $path = '', $scheme = null ) {
		return ( $GLOBALS['wp_test_site_url'] ?? 'https://example.com' ) . $path;
	}
}

if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( $url, $component = -1 ) {
		return parse_url( $url, $component );
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	function sanitize_text_field( $str ) {
		$str = (string) $str;
		$str = preg_replace( '/[\r\n\t\0\x0B]/', '', $str );
		return trim( $str );
	}
}

if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( $value ) {
		return is_string( $value ) ? stripslashes( $value ) : $value;
	}
}

// Object cache (in-memory map, no TTL enforcement).
if ( ! isset( $GLOBALS['wp_test_object_cache'] ) ) {
	$GLOBALS['wp_test_object_cache'] = array();
}
if ( ! isset( $GLOBALS['wp_test_using_ext_cache'] ) ) {
	$GLOBALS['wp_test_using_ext_cache'] = false;
}
if ( ! function_exists( 'wp_using_ext_object_cache' ) ) {
	function wp_using_ext_object_cache( $using = null ) {
		if ( null !== $using ) {
			$GLOBALS['wp_test_using_ext_cache'] = (bool) $using;
		}
		return ! empty( $GLOBALS['wp_test_using_ext_cache'] );
	}
}
if ( ! function_exists( 'wp_cache_get' ) ) {
	function wp_cache_get( $key, $group = '' ) {
		return $GLOBALS['wp_test_object_cache'][ $group ][ $key ] ?? false;
	}
}
if ( ! function_exists( 'wp_cache_add' ) ) {
	function wp_cache_add( $key, $value, $group = '', $ttl = 0 ) {
		if ( isset( $GLOBALS['wp_test_object_cache'][ $group ][ $key ] ) ) {
			return false;
		}
		$GLOBALS['wp_test_object_cache'][ $group ][ $key ] = $value;
		return true;
	}
}
if ( ! function_exists( 'wp_cache_set' ) ) {
	function wp_cache_set( $key, $value, $group = '', $ttl = 0 ) {
		$GLOBALS['wp_test_object_cache'][ $group ][ $key ] = $value;
		return true;
	}
}
if ( ! function_exists( 'wp_cache_incr' ) ) {
	function wp_cache_incr( $key, $offset = 1, $group = '' ) {
		if ( ! isset( $GLOBALS['wp_test_object_cache'][ $group ][ $key ] ) ) {
			return false;
		}
		$current = (int) $GLOBALS['wp_test_object_cache'][ $group ][ $key ];
		$new     = $current + (int) $offset;
		$GLOBALS['wp_test_object_cache'][ $group ][ $key ] = $new;
		return $new;
	}
}
if ( ! function_exists( 'wp_cache_delete' ) ) {
	function wp_cache_delete( $key, $group = '' ) {
		unset( $GLOBALS['wp_test_object_cache'][ $group ][ $key ] );
		return true;
	}
}

// Minimal WP_REST_Request stub — only the surface OriginValidator needs.
if ( ! class_exists( 'WP_REST_Request' ) ) {
	class WP_REST_Request {
		private array $headers = array();
		private array $params  = array();

		public function set_header( string $name, string $value ): void {
			$this->headers[ strtolower( $name ) ] = $value;
		}

		/**
		 * Mirrors WP_REST_Request::get_header — case-insensitive lookup,
		 * returns null when absent.
		 *
		 * @param string $name Header name.
		 * @return string|null
		 */
		public function get_header( $name ) {
			return $this->headers[ strtolower( (string) $name ) ] ?? null;
		}

		/** Set a query/body parameter for testing. */
		public function set_param( string $name, $value ): void {
			$this->params[ $name ] = $value;
		}

		/** Mirrors WP_REST_Request::get_params. */
		public function get_params(): array {
			return $this->params;
		}
	}
}

if ( ! class_exists( 'WP_Ability' ) ) {
	class WP_Ability {
		private $name;
		private $label;
		private $description;
		private $category;
		private $meta;
		private $input_schema;
		private $output_schema;

		public function __construct( $name = '', $args = array() ) {
			$this->name          = $name;
			$this->label         = $args['label'] ?? '';
			$this->description   = $args['description'] ?? '';
			$this->category      = $args['category'] ?? '';
			$this->meta          = $args['meta'] ?? array();
			$this->input_schema  = $args['input_schema'] ?? array();
			$this->output_schema = $args['output_schema'] ?? array();
		}

		public function get_name() {
			return $this->name;
		}

		public function get_label() {
			return $this->label;
		}

		public function get_description() {
			return $this->description;
		}

		public function get_category() {
			return $this->category;
		}

		public function get_meta() {
			return $this->meta;
		}

		public function get_input_schema() {
			return $this->input_schema;
		}

		public function get_output_schema() {
			return $this->output_schema;
		}
	}
}

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		private $code;
		private $message;
		private $data;

		public function __construct( $code = '', $message = '', $data = '' ) {
			$this->code    = $code;
			$this->message = $message;
			$this->data    = $data;
		}

		public function get_error_code() {
			return $this->code;
		}

		public function get_error_message() {
			return $this->message;
		}

		public function get_error_data() {
			return $this->data;
		}
	}
}

// ---- OAuth stubs ----

if ( ! function_exists( 'is_ssl' ) ) {
	function is_ssl() {
		return ! empty( $_SERVER['HTTPS'] ) && $_SERVER['HTTPS'] !== 'off';
	}
}

if ( ! function_exists( 'rest_url' ) ) {
	function rest_url( $path = '' ) {
		$base = ( $GLOBALS['wp_test_home_url'] ?? 'https://example.com' ) . '/wp-json/';
		return $base . ltrim( $path, '/' );
	}
}

if ( ! function_exists( 'esc_url_raw' ) ) {
	function esc_url_raw( $url ) {
		return filter_var( (string) $url, FILTER_SANITIZE_URL ) ?: '';
	}
}

if ( ! function_exists( 'status_header' ) ) {
	function status_header( $code ) {
		// No-op in test environment.
	}
}

if ( ! function_exists( 'wp_generate_uuid4' ) ) {
	function wp_generate_uuid4() {
		return sprintf(
			'%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
			mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),
			mt_rand( 0, 0xffff ),
			mt_rand( 0, 0x0fff ) | 0x4000,
			mt_rand( 0, 0x3fff ) | 0x8000,
			mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
		);
	}
}

if ( ! function_exists( 'absint' ) ) {
	function absint( $maybeint ) {
		return abs( (int) $maybeint );
	}
}

// ---- Admin-page stubs (Phase 2 UI consolidation) ----

if ( ! isset( $GLOBALS['wp_test_redirect'] ) ) {
	$GLOBALS['wp_test_redirect'] = null;
}

if ( ! function_exists( 'add_query_arg' ) ) {
	function add_query_arg( $args, $url = '' ) {
		// Two-arg form: array of args + base URL.
		$query = parse_url( $url, PHP_URL_QUERY );
		$existing = array();
		if ( $query ) {
			parse_str( $query, $existing );
		}
		$merged = array_merge( $existing, (array) $args );
		$base   = strtok( $url, '?' );
		return $base . ( empty( $merged ) ? '' : '?' . http_build_query( $merged ) );
	}
}

if ( ! function_exists( 'admin_url' ) ) {
	function admin_url( $path = '' ) {
		return ( $GLOBALS['wp_test_admin_url'] ?? 'https://example.com/wp-admin/' ) . ltrim( (string) $path, '/' );
	}
}

if ( ! function_exists( 'network_admin_url' ) ) {
	function network_admin_url( $path = '' ) {
		return ( $GLOBALS['wp_test_network_admin_url'] ?? 'https://example.com/wp-admin/network/' ) . ltrim( (string) $path, '/' );
	}
}

if ( ! function_exists( 'is_network_admin' ) ) {
	function is_network_admin() {
		return ! empty( $GLOBALS['wp_test_is_network_admin'] );
	}
}

if ( ! class_exists( 'WickedEvolutions\\McpAdapter\\Tests\\RedirectException' ) ) {
	// Sentinel — production code calls `exit;` after wp_safe_redirect(); by
	// throwing here we capture the redirect target and unwind the stack
	// before `exit;` executes. Tests catch this via expectException().
	class WickedEvolutions_McpAdapter_Tests_RedirectException extends \RuntimeException {}
	class_alias(
		'WickedEvolutions_McpAdapter_Tests_RedirectException',
		'WickedEvolutions\\McpAdapter\\Tests\\RedirectException'
	);
}

if ( ! function_exists( 'wp_safe_redirect' ) ) {
	function wp_safe_redirect( $location, $status = 302 ) {
		$GLOBALS['wp_test_redirect'] = array(
			'location' => (string) $location,
			'status'   => (int) $status,
		);
		throw new \WickedEvolutions\McpAdapter\Tests\RedirectException( (string) $location );
	}
}

if ( ! function_exists( 'add_menu_page' ) ) {
	function add_menu_page( $page_title, $menu_title, $capability, $menu_slug, $callback = '', $icon = '', $position = null ) {
		$GLOBALS['wp_test_menu_pages'][] = compact( 'page_title', 'menu_title', 'capability', 'menu_slug', 'callback', 'icon', 'position' );
		return $menu_slug;
	}
}

if ( ! function_exists( 'esc_attr' ) ) {
	function esc_attr( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_url' ) ) {
	function esc_url( $url ) {
		return htmlspecialchars( (string) $url, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_html_e' ) ) {
	function esc_html_e( $text, $domain = 'default' ) {
		echo htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_attr_e' ) ) {
	function esc_attr_e( $text, $domain = 'default' ) {
		echo htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_textarea' ) ) {
	function esc_textarea( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_js' ) ) {
	function esc_js( $text ) {
		return addslashes( (string) $text );
	}
}

if ( ! function_exists( 'wp_nonce_field' ) ) {
	function wp_nonce_field( $action = -1, $name = '_wpnonce', $referer = true, $echo = true ) {
		$out = '<input type="hidden" name="' . htmlspecialchars( (string) $name ) . '" value="test-nonce" />';
		if ( $echo ) {
			echo $out;
		}
		return $out;
	}
}

if ( ! function_exists( 'submit_button' ) ) {
	function submit_button( $text = null, $type = 'primary', $name = 'submit', $wrap = true, $other = null ) {
		echo '<input type="submit" value="' . htmlspecialchars( (string) $text ) . '" />';
	}
}

if ( ! function_exists( 'settings_errors' ) ) {
	function settings_errors( $setting = '', $sanitize = false, $hide_on_update = false ) {
		// No-op in test environment.
	}
}

if ( ! function_exists( 'checked' ) ) {
	function checked( $checked, $current = true, $echo = true ) {
		$result = (string) $checked === (string) $current ? ' checked="checked"' : '';
		if ( $echo ) {
			echo $result;
		}
		return $result;
	}
}

// ---- Phase 3 stubs ----

// Minimal $wpdb stub for tests that touch DB-fronting classes (ClientRegistry::list_active(),
// PriorGrantLookup, ConnectedBridgesTab::latest_token_for, etc.). Tests that need DB fixtures
// can swap individual methods on $GLOBALS['wpdb'] before invoking the unit under test.
if ( ! isset( $GLOBALS['wpdb'] ) ) {
	$GLOBALS['wpdb'] = new class {
		public string $prefix = 'wp_';

		/** Stored last-prepared query, for tests that want to assert against it. */
		public string $last_prepared = '';

		/** Default empty results — tests can override per-instance. */
		public function get_results( $query ) { return array(); }
		public function get_row( $query )     { return null; }
		public function get_var( $query )     { return null; }
		public function prepare( $query, ...$args ) {
			$this->last_prepared = (string) $query;
			return $query;
		}
		public function insert( $table, $data, $format = null ) { return 1; }
		public function update( $table, $data, $where, $format = null, $where_format = null ) { return 1; }
		public function query( $sql ) { return true; }
	};
}


if ( ! function_exists( '_n' ) ) {
	function _n( $single, $plural, $number, $domain = 'default' ) {
		return ( (int) $number === 1 ) ? $single : $plural;
	}
}

if ( ! function_exists( 'wp_login_url' ) ) {
	function wp_login_url( $redirect_to = '' ) {
		$base = ( $GLOBALS['wp_test_home_url'] ?? 'https://example.com' ) . '/wp-login.php';
		return '' === $redirect_to ? $base : $base . '?redirect_to=' . rawurlencode( $redirect_to );
	}
}

if ( ! function_exists( 'wp_verify_nonce' ) ) {
	function wp_verify_nonce( $nonce, $action = -1 ) {
		// In tests, the nonce stub from wp_nonce_field() always emits 'test-nonce'.
		return 'test-nonce' === $nonce ? 1 : false;
	}
}

if ( ! function_exists( 'wp_date' ) ) {
	function wp_date( $format, $timestamp = null, $timezone = null ) {
		return gmdate( $format, $timestamp ?? time() );
	}
}

if ( ! function_exists( 'get_bloginfo' ) ) {
	function get_bloginfo( $show = '' ) {
		return $GLOBALS['wp_test_bloginfo'][ $show ] ?? 'Test Site';
	}
}

if ( ! function_exists( 'get_userdata' ) ) {
	function get_userdata( $user_id ) {
		$user = $GLOBALS['wp_test_users'][ (int) $user_id ] ?? null;
		if ( ! $user ) {
			return false;
		}
		$obj = new stdClass();
		$obj->ID            = (int) $user_id;
		$obj->user_login    = (string) ( $user['user_login']   ?? 'user_' . $user_id );
		$obj->display_name  = (string) ( $user['display_name'] ?? $obj->user_login );
		$obj->roles         = (array)  ( $user['roles']        ?? array() );
		return $obj;
	}
}

// ---- WordPress constants (if not already defined by the test environment). ----
if ( ! defined( 'DAY_IN_SECONDS' ) )  { define( 'DAY_IN_SECONDS',  86400 ); }
if ( ! defined( 'HOUR_IN_SECONDS' ) ) { define( 'HOUR_IN_SECONDS', 3600 ); }

// ---- Multisite stubs ----

if ( ! function_exists( 'is_multisite' ) ) {
	function is_multisite() {
		return ! empty( $GLOBALS['wp_test_is_multisite'] );
	}
}

// site_transient stubs — backed by a separate in-memory store so they are
// always independent of per-blog transients in tests.
if ( ! isset( $GLOBALS['wp_test_site_transients'] ) ) {
	$GLOBALS['wp_test_site_transients'] = array();
}

if ( ! function_exists( 'get_site_transient' ) ) {
	function get_site_transient( $key ) {
		$entry = $GLOBALS['wp_test_site_transients'][ $key ] ?? null;
		if ( ! $entry ) {
			return false;
		}
		if ( $entry['expires'] < time() ) {
			unset( $GLOBALS['wp_test_site_transients'][ $key ] );
			return false;
		}
		return $entry['value'];
	}
}

if ( ! function_exists( 'set_site_transient' ) ) {
	function set_site_transient( $key, $value, $ttl = 0 ) {
		$GLOBALS['wp_test_site_transients'][ $key ] = array(
			'value'   => $value,
			'expires' => time() + (int) $ttl,
		);
		return true;
	}
}

if ( ! function_exists( 'delete_site_transient' ) ) {
	function delete_site_transient( $key ) {
		unset( $GLOBALS['wp_test_site_transients'][ $key ] );
		return true;
	}
}

// wp_next_scheduled / wp_schedule_event / wp_unschedule_event stubs (cron tests).
if ( ! isset( $GLOBALS['wp_test_cron'] ) ) {
	$GLOBALS['wp_test_cron'] = array();
}

if ( ! function_exists( 'wp_next_scheduled' ) ) {
	function wp_next_scheduled( $hook ) {
		return $GLOBALS['wp_test_cron'][ $hook ] ?? false;
	}
}

if ( ! function_exists( 'wp_schedule_event' ) ) {
	function wp_schedule_event( $timestamp, $recurrence, $hook ) {
		$GLOBALS['wp_test_cron'][ $hook ] = (int) $timestamp;
		return true;
	}
}

if ( ! function_exists( 'wp_unschedule_event' ) ) {
	function wp_unschedule_event( $timestamp, $hook ) {
		unset( $GLOBALS['wp_test_cron'][ $hook ] );
		return true;
	}
}

if ( ! function_exists( 'number_format' ) ) {
	// PHP built-in — present in all environments; this guard is just documentation.
	// No-op stub: number_format is always available.
}

if ( ! function_exists( 'update_option' ) ) {
	function update_option( $option, $value, $autoload = null ) {
		$GLOBALS['wp_test_options'][ $option ] = $value;
		return true;
	}
}

// ---- Token endpoint response sentinels ----
//
// token_success() and token_error() in the real helpers call exit after emitting
// output, which would kill the test process. We define sentinel-throwing versions
// here before helpers.php loads; the function_exists() guards in helpers.php will
// leave these stubs in place for all unit tests.
//
// Tests that need to assert on the response body can catch the sentinel and inspect
// its properties. Tests that only care about side-effects (DB writes, rate-limit
// transients) can let the sentinel propagate — PHPUnit will report an unexpected
// exception, so tests must catch it explicitly.

if ( ! class_exists( 'WickedEvolutions_McpAdapter_Tests_TokenResponseSentinel' ) ) {
	class WickedEvolutions_McpAdapter_Tests_TokenResponseSentinel extends \RuntimeException {
		public array  $body    = array();
		public int    $status  = 200;
		public string $context = '';

		public function __construct( array $body, int $status, string $context ) {
			$this->body    = $body;
			$this->status  = $status;
			$this->context = $context;
			parent::__construct( 'Token endpoint response: ' . $context . ' HTTP ' . $status );
		}
	}
	class_alias(
		'WickedEvolutions_McpAdapter_Tests_TokenResponseSentinel',
		'WickedEvolutions\\McpAdapter\\Tests\\TokenResponseSentinel'
	);
}

if ( ! function_exists( 'token_success' ) ) {
	function token_success( array $body, int $status = 200 ): never {
		throw new \WickedEvolutions\McpAdapter\Tests\TokenResponseSentinel( $body, $status, 'success' );
	}
}

if ( ! function_exists( 'token_error' ) ) {
	function token_error( string $error, string $description, int $status = 400 ): never {
		throw new \WickedEvolutions\McpAdapter\Tests\TokenResponseSentinel(
			array( 'error' => $error, 'error_description' => $description ),
			$status,
			'error'
		);
	}
}

// Autoload global OAuth helpers so all tests can call them.
// helpers.php is in the global namespace and guards each function with function_exists().
require_once dirname( __DIR__ ) . '/src/Auth/OAuth/helpers.php';
