# Changelog

## [1.0.9] - 2026-03-16

### Added
- `input_schema` included in error `_metadata` for self-correcting AI agents — when a tool call fails, the response now includes the expected parameter schema

## [1.0.8] - 2026-03-15

### Fixed
- WP_Error details now pass through to MCP client — error code, message, and data are preserved instead of generic "An error occurred"

## [1.0.7] - 2026-03-14

### Added
- Native MCP protocol version negotiation — server-side handling

## [1.0.6] - 2026-03-13

### Changed
- Version bump for deployment alignment

## [1.0.5] - 2026-03-13

### Added
- License manager with FluentCart integration
- Plugin updater for auto-updates via FluentCart
- Network admin UI for multisite
- `discover-abilities` presents Knowledge Layer choices to user (boot nudge)

### Removed
- Boot gate requirement

## [1.0.4] - 2026-03-12

### Added
- `mcp.public` flag on `discover-abilities` so it works via `execute-ability`
- Filtered discovery: category, annotation, and search filters

## [1.0.3] - 2026-03-12

### Added
- Boot gate and structured `next_action` sequences
- `get-started` directs AI to `knowledge/boot` when Knowledge Layer exists

## [1.0.2] - 2026-03-11

### Fixed
- `empty()` null conversion blocking all ability execution — replaced with `??` / `isset()`
- Pass null to no-schema abilities in `execute-ability` meta-ability
- Align `McpAdapter::VERSION` constant with plugin header

---

## [1.0.1] - 2026-03-09

### Fixed
- `mcp-adapter/get-ability-info` — `show_in_rest: true` added so ability doesn't gate itself
- `mcp-adapter/batch-execute` — three bugs (hardcoded server ID, missing per-item try/catch, response format mismatch)

---

## [1.0.0] - 2026-03-11

### Changed
- **Renamed:** MCP Adapter for WordPress → **Abilities MCP Adapter** (WordPress.org trademark compliance)
- Plugin slug: `mcp-adapter-for-wordpress` → `abilities-mcp-adapter`
- Namespace: `WickedEvolutions\McpAdapter` (unchanged)
- GitHub repo: `Wicked-Evolutions/abilities-mcp-adapter`
- Deployed to helenawillow.com and wickedevolutions.com with license + permission migration

---

## [1.0.1-alpha] - 2026-03-09

### Fixed
- `mcp-adapter/get-ability-info` — added `show_in_rest: true` to registration so the ability no longer gates itself out of its own permission check via `is_ability_mcp_public()`
- `mcp-adapter/batch-execute` — three bugs fixed:
  1. Hardcoded `'mcp-adapter-default-server'` replaced with `get_servers()` + `reset()` — works regardless of server ID
  2. Per-item `try/catch` added around `call_tool()` — one failing tool no longer aborts the entire batch
  3. Response format: `_metadata` stripped, `{error}` protocol errors converted to wire-format `{content, isError: true}` — responses now match what the bridge and LLM expect

---

## [1.0.0-alpha] - 2026-03-08

First standalone release. Fully decoupled from upstream `wordpress/mcp-adapter` Composer
package — all code lives under `WickedEvolutions\McpAdapter` namespace with PSR-4 autoloading.

### Added
- `McpServerConfig` immutable config object replacing 13-parameter God Constructor
- `McpAnnotationMapper::build_from_ability()` — single method for annotation injection across tools, resources, and prompts
- Permission metadata: per-ability `permission` (read/write/delete) and `enabled` state in MCP annotations
- Admin settings page (Settings → MCP Abilities) for per-ability enable/disable controls
- Discovery gate (XP5): abilities with `show_in_rest` or `meta.mcp.public` become MCP tools
- `mcp-adapter/batch-execute` — 4th built-in tool for multi-tool single round-trip
- `McpErrorMapper` — centralized WP_Error to MCP error code mapping
- Annotation injection: `category`, `tier`, `bridge_hints` flow from ability meta into MCP annotations
- 282 unit tests (PHPUnit) covering handlers, core classes, annotation mapping, schema transformation

### Changed
- Namespace: `WickedEvolutions\McpAdapter` (was `Jelix\McpAdapter`)
- PHP requirement: 8.0+ (was 7.4)
- WordPress requirement: 6.9+ (Abilities API)
- All code owned — no Composer vendor dependency on upstream package
- `create_server_from_config()` accepts `McpServerConfig` instead of 13 positional parameters

### Removed
- `composer.json` vendor dependency on `wordpress/mcp-adapter`
- Vendor autoloader fallback — uses project's own PSR-4 autoloader

---

## Pre-1.0 History

Versions 2.1.0–2.3.0 were wrapper releases around the upstream `wordpress/mcp-adapter`
Composer package. The version numbers reflected the wrapper, not the underlying library.
All functionality has been absorbed into the 1.0.0-alpha standalone codebase.

---

## License

GPL-2.0-or-later
