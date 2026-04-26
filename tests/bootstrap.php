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

if ( ! function_exists( 'esc_html__' ) ) {
	function esc_html__( $text, $domain = 'default' ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

// Filter / action stubs — record-only, with a hook for tests that want to
// inject filter return values via $GLOBALS['wp_test_filters'][ $hook ].
if ( ! function_exists( 'apply_filters' ) ) {
	function apply_filters( $hook, $value ) {
		if ( isset( $GLOBALS['wp_test_filters'][ $hook ] ) ) {
			$callback = $GLOBALS['wp_test_filters'][ $hook ];
			$args     = func_get_args();
			array_shift( $args ); // drop hook name
			return call_user_func_array( $callback, $args );
		}
		return $value;
	}
}

if ( ! function_exists( 'do_action' ) ) {
	function do_action( $hook, ...$args ) {
		return null;
	}
}

if ( ! function_exists( 'add_action' ) ) {
	function add_action( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
		return true;
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
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
