# Changelog

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
