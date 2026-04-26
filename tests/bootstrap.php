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
		// Tests don't assert action invocations.
		return null;
	}
}

if ( ! function_exists( 'add_action' ) ) {
	function add_action( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
		return true;
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
