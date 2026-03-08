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
