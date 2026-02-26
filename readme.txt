=== MCP Adapter for WordPress ===
Contributors: influencentricity
Tags: mcp, ai, abilities, model-context-protocol, automation
Requires at least: 6.9
Tested up to: 6.9.1
Requires PHP: 7.4
Stable tag: 2.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Packages the official WordPress MCP Adapter as an installable plugin. Upload, activate, and your abilities become MCP tools.

== Description ==

MCP Adapter for WordPress packages the official `wordpress/mcp-adapter` library as a standard WordPress plugin that you can install via zip upload — no Composer or CLI required.

Once activated, the plugin automatically discovers all abilities registered via `wp_register_ability()` and exposes them as MCP (Model Context Protocol) tools. This lets AI assistants like Claude, ChatGPT, and other MCP-compatible clients interact with your WordPress site through the official Abilities API.

**What's included:**

* Automatic discovery of all registered WordPress abilities
* Three built-in discovery tools (discover-abilities, get-ability-info, execute-ability)
* MCP tool validation (silently drops invalid tools instead of breaking the entire tool list)
* WP-CLI command: `wp mcp-adapter serve` for stdio transport
* Pre-bundled Composer dependencies — no build step needed

**Works with:**

* [Abilities Suite for WordPress](https://github.com/Influencentricity/abilities-suite-for-wordpress) — 93 core abilities across 17 modules
* Any plugin that registers abilities via `wp_register_ability()`
* Any MCP-compatible AI client (Claude Desktop, Claude Code, etc.)

== Installation ==

1. Download the plugin zip file.
2. In WordPress admin, go to Plugins > Add New > Upload Plugin.
3. Upload the zip file and click Install Now.
4. Activate the plugin (or Network Activate on multisite).

For remote AI access, use the [MCP SSH Bridge](https://github.com/Influencentricity/mcp-ssh-bridge):

    node mcp-ssh-bridge.js --host=my-server --path=/var/www/html

== Frequently Asked Questions ==

= Do I need the Abilities API plugin? =

No. The Abilities API is included in WordPress 6.9+ core. This plugin requires WordPress 6.9 or later.

= Do I need to run Composer? =

No. All dependencies are pre-bundled in the plugin zip. Just upload and activate.

= How do I connect an AI tool? =

Use WP-CLI over SSH: `wp mcp-adapter serve`. For a transport bridge, see the MCP SSH Bridge or MCP HTTP Bridge projects.

= Does this work on multisite? =

Yes. Network activate to make MCP tools available on all sites.

== Changelog ==

= 2.0.0 =
* MCP tool validation enabled by default
* Requires WordPress 6.9+ (Abilities API in core)
* Pre-bundled dependencies for zip distribution

= 1.0.0 =
* Initial release
* Automatic ability discovery and MCP tool exposure
* WP-CLI `wp mcp-adapter serve` command
