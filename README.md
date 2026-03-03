# MCP Adapter for WordPress

Packages the official WordPress MCP Adapter (`wordpress/mcp-adapter`) as a standard installable plugin. Upload, activate, and all your registered WordPress abilities automatically become MCP tools — zero configuration required.

## What This Does

This plugin bundles the official `wordpress/mcp-adapter` Composer library and configures it to automatically discover and expose every ability registered via `wp_register_ability()` as an MCP tool. It also registers three built-in discovery tools:

- `mcp-adapter/discover-abilities` — list all available abilities
- `mcp-adapter/get-ability-info` — get schema and metadata for a specific ability
- `mcp-adapter/execute-ability` — execute an ability with input parameters

## Requirements

- WordPress 6.9+ (Abilities API in core)
- PHP 7.4+

## Installation

1. Download the plugin zip file
2. Go to Plugins → Add New → Upload Plugin
3. Upload and activate

All Composer dependencies are pre-bundled — no `composer install` needed.

## Usage with MCP Bridge

For remote access from AI tools like Claude Code, use the [WP Abilities MCP](https://github.com/Influencentricity/wp-abilities-mcp) unified bridge:

```json
{
  "mcpServers": {
    "wordpress": {
      "command": "node",
      "args": ["/path/to/wp-abilities-mcp/wp-abilities-mcp.js"]
    }
  }
}
```

Supports both HTTP (primary) and SSH (legacy) transports with multi-site routing.

## Validation Filter

The plugin enables MCP tool validation by default:

```php
add_filter( 'mcp_adapter_validation_enabled', '__return_true' );
```

This ensures only abilities with valid JSON Schema are exposed as MCP tools. If tools are missing, check that ability schemas include proper `type` fields and that `type: "array"` properties have `items` definitions.

## How Abilities Become MCP Tools

Any ability with `'mcp' => array('public' => true, 'type' => 'tool')` in its `meta` array is automatically included in the MCP server's tool list. The adapter reads the ability's `input_schema` and `output_schema` to generate MCP-compatible tool definitions.

## Bundled Dependencies

- `wordpress/mcp-adapter: ^0.4.0` — official MCP protocol handler
- `automattic/jetpack-autoloader: ^5.0` — classmap autoloader

## Version

**Current:** 2.2.0

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Author

[Influencentricity](https://influencentricity.com)

## License

GPL-2.0-or-later
