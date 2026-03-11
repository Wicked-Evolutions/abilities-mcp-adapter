=== MCP Adapter for WordPress ===
Contributors: influencentricity
Tags: mcp, ai, abilities, model-context-protocol, automation
Requires at least: 6.9
Tested up to: 6.9.1
Requires PHP: 7.4
Stable tag: 1.0.2-alpha
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Packages the official WordPress MCP Adapter as an installable plugin. Upload, activate, and your abilities become MCP tools.

== Description ==

MCP Adapter for WordPress packages the official `wordpress/mcp-adapter` library as a standard WordPress plugin that you can install via zip upload — no Composer or CLI required.

Once activated, the plugin automatically discovers all abilities registered via `wp_register_ability()` and exposes them as MCP (Model Context Protocol) tools. This lets any AI client or IDE that supports MCP interact with your WordPress site through the official Abilities API.

**What's included:**

* Automatic discovery of all registered WordPress abilities
* Three built-in discovery tools (discover-abilities, get-ability-info, execute-ability)
* MCP tool validation (silently drops invalid tools instead of breaking the entire tool list)
* WP-CLI command: `wp mcp-adapter serve` for stdio transport
* Pre-bundled Composer dependencies — no build step needed

**Works with:**

* [Abilities Suite for WordPress](https://github.com/Influencentricity/abilities-suite-for-wordpress) — 138 abilities across 18 modules
* Any plugin that registers abilities via `wp_register_ability()`
* Any MCP-compatible AI client or IDE (Claude Code, Claude Desktop, Gemini CLI, Cursor, Windsurf, VS Code, etc.)

== Installation ==

1. Download the plugin zip file.
2. In WordPress admin, go to Plugins > Add New > Upload Plugin.
3. Upload the zip file and click Install Now.
4. Activate the plugin (or Network Activate on multisite).

For remote AI access, use the [WP Abilities MCP](https://github.com/Influencentricity/wp-abilities-mcp) bridge:

    node wp-abilities-mcp.js

== Frequently Asked Questions ==

= Do I need the Abilities API plugin? =

No. The Abilities API is included in WordPress 6.9+ core. This plugin requires WordPress 6.9 or later.

= Do I need to run Composer? =

No. All dependencies are pre-bundled in the plugin zip. Just upload and activate.

= How do I connect an AI tool? =

Use WP-CLI over SSH: `wp mcp-adapter serve`. For a transport bridge, see [WP Abilities MCP](https://github.com/Influencentricity/wp-abilities-mcp) — a unified multi-site MCP bridge with HTTP and SSH transport support.

= Does this work on multisite? =

Yes. Network activate to make MCP tools available on all sites.

== Changelog ==

= 1.0.2-alpha =
* Fix: `empty()` null conversion blocking ability execution — parameters passed as `[]` were converted to `null`, rejected by WordPress core schema validation
* Fix: `ability_missing_input_schema` — no-arg abilities called through the meta-ability now correctly receive `null` input instead of empty `{}`

= 1.0.1-alpha =
* Fix: batch-execute reliability improvements

= 1.0.0-alpha =
* Standalone MCP Adapter, fully decoupled from upstream `wordpress/mcp-adapter` Composer package
* New `WickedEvolutions\McpAdapter` namespace
* HTTP transport with session management
* Admin settings page (Settings > MCP Abilities) for per-ability enable/disable
* Batch execute tool (max 20 abilities per request)
* Permission metadata (read/write/delete) flows through MCP annotations

= 2.2.0 =
* Added batch-execute tool
* Admin settings page for ability management

= 2.1.0 =
* HTTP transport support
* MCP annotations (readonly, destructive, idempotent)
* Permission metadata on tool definitions

= 2.0.0 =
* MCP tool validation enabled by default
* Requires WordPress 6.9+ (Abilities API in core)
* Pre-bundled dependencies for zip distribution

= 1.0.0 =
* Initial release
* Automatic ability discovery and MCP tool exposure
* WP-CLI `wp mcp-adapter serve` command
