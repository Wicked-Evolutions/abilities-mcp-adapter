=== Abilities MCP Adapter ===
Contributors: wickedevolutions
Tags: mcp, ai, abilities, model-context-protocol, automation
Requires at least: 6.9
Tested up to: 6.9.1
Requires PHP: 8.2
Stable tag: 1.4.9
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Exposes WordPress abilities as MCP tools. Upload, activate, and your abilities become AI-operable.

== Description ==

Abilities MCP Adapter exposes all registered WordPress abilities as MCP (Model Context Protocol) tools. Once activated, any AI client or IDE that supports MCP can discover and execute abilities on your WordPress site through a typed, validated, permission-checked protocol.

**What's included:**

* Automatic discovery of all registered WordPress abilities
* Built-in tools: discover-abilities, get-ability-info, execute-ability, batch-execute
* Batch execution — up to 20 abilities per call
* Get-started onboarding tool for AI agent orientation
* Per-ability permission controls via admin dashboard
* MCP tool validation (silently drops invalid tools)
* WP-CLI command: `wp mcp-adapter serve` for stdio transport
* Pre-bundled Composer dependencies — no build step needed

**Works with:**

* [Abilities for AI](https://github.com/Wicked-Evolutions/abilities-for-ai) — 138 abilities across 18 modules
* Any plugin that registers abilities via `wp_register_ability()`
* Any MCP-compatible AI client (Claude Code, Claude Desktop, Gemini CLI, Cursor, Windsurf, VS Code, etc.)

== Installation ==

1. Download the plugin zip file.
2. In WordPress admin, go to Plugins > Add New > Upload Plugin.
3. Upload the zip file and click Install Now.
4. Activate the plugin (or Network Activate on multisite).

For remote AI access, use the [Abilities MCP](https://github.com/Wicked-Evolutions/abilities-mcp) bridge:

    node abilities-mcp.js

== Frequently Asked Questions ==

= Do I need the Abilities API plugin? =

No. The Abilities API is included in WordPress 6.9+ core. This plugin requires WordPress 6.9 or later.

= Do I need to run Composer? =

No. All dependencies are pre-bundled in the plugin zip. Just upload and activate.

= How do I connect an AI tool? =

Use WP-CLI over SSH: `wp mcp-adapter serve`. For a transport bridge, see [Abilities MCP](https://github.com/Wicked-Evolutions/abilities-mcp) — a unified multi-site MCP bridge with HTTP and SSH transport support.

= Does this work on multisite? =

Yes. Network activate to make MCP tools available on all sites.

== Screenshots ==

1. Admin dashboard — per-ability permission controls

== Changelog ==

See [CHANGELOG.md](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/blob/main/CHANGELOG.md) for the full version history. Recent versions:

= 1.4.9 =
* Fixed: McpToolValidator no longer rejects JSON-spec-correct stdClass empty-object schemas (#125) — adapter aligned with WordPress Abilities API contract per Principle 3 + Principle 4.
* Added: FluentPlayer ability category in OAuth scope registry — abilities grantable + executable under OAuth (#118).
* Fixed: Documented boot entrypoint mcp-adapter/get-started now registered with default server (#87 S3 via #119).
* Chore: ABILITIES_MCP_ADAPTER_VERSION constant aligned with plugin header.
* Docs: readme.txt Stable tag + Requires PHP corrected; changelog backfilled (#124).

= 1.4.8 =
* Fixed: tools/list + tools/list/all schema-metadata exemption extended to method-level paths (#113) — completes the per-ability exemption shipped in 1.4.6.

= 1.4.7 =
* Documentation: README rewrite for OAuth 2.1 resource server, Connected Bridges admin UI, layered-permissions surface coverage.
* Corrected: PHP requirement 8.0+ → 8.2+ (matches composer.json + plugin header).

= 1.4.6 =
* Security: Bucket 3 redaction extended to prefixed email field variants (#103).
* Fixed: mcp-adapter/get-ability-info schemas no longer corrupted by redaction (#105).
* Fixed: OAuth scope coverage for site + surecart-ecommerce categories, with CI drift test pinning the contract (#101, #102).

= 1.4.5 =
* Fixed: Subsite authorize endpoint dispatches under path-style prefix (#90).
* Known limitation: role downgrade applies on interactive consent only — auto-approve refresh issues full-caps tokens (#94).
* Known limitation: mcp-adapter/batch-execute deferred to post-alpha (#104).

= 1.0.0 =
* Initial public release under Wicked Evolutions
* Batch execute tool (max 20 abilities per request)
* Get-started onboarding tool for AI agent orientation
* Per-ability permission controls via admin dashboard (Settings > MCP Abilities)
* HTTP transport with session management
* MCP annotations (readonly, destructive, idempotent) on all tools
* MCP tool validation — silently drops invalid tools
* WP-CLI `wp mcp-adapter serve` command for stdio transport
* Pre-bundled Composer dependencies for zip distribution
* Requires WordPress 6.9+ (Abilities API in core)
* Requires PHP 8.0+

== Upgrade Notice ==

= 1.4.9 =
Hotfix for Astra-pattern stdClass schema rejection (#125) plus FluentPlayer OAuth scope (#118), boot-tool allowlist fix (#87 S3), and readme.txt metadata corrections. Drop-in replacement for v1.4.8.

= 1.0.0 =
First public release. Install and activate to expose WordPress abilities as MCP tools.
