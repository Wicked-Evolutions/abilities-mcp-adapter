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

## Usage with SSH Bridge

For remote access from AI tools like Claude Code, use the [MCP SSH Bridge](https://github.com/Influencentricity/mcp-ssh-bridge):

```bash
node mcp-ssh-bridge.js --host=my-server --path=/var/www/html --user=wp_agent
```

## How Abilities Become MCP Tools

Any ability with `'mcp' => array('public' => true, 'type' => 'tool')` in its `meta` array is automatically included in the MCP server's tool list. The adapter reads the ability's `input_schema` and `output_schema` to generate MCP-compatible tool definitions.

## Bundled Dependencies

- `wordpress/mcp-adapter: ^0.4.0` — official MCP protocol handler
- `automattic/jetpack-autoloader: ^5.0` — classmap autoloader

## Version

**Current:** 2.0.0

## Author

[Influencentricity](https://influencentricity.com)

## License

GPL-2.0-or-later
