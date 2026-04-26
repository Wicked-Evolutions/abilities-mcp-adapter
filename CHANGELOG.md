# Changelog

## [Unreleased] — DB-3 (held for public-alpha hardening Launch Gate)

### Added — Safety Settings UI + AI-callable settings abilities
- New admin page **Settings → MCP Safety** with four sections:
  1. Master toggle (off requires checkbox confirmation; Bucket 1 secrets always filtered).
  2. Redaction keyword list — Bucket 1 read-only; Bucket 2 with per-default warning; Bucket 3 with per-default no warning; custom-add input (Bucket 2 or 3 only); restore defaults.
  3. Per-ability exemptions — two columns (Bucket 3 left, Bucket 2 right with confirm-on-add warning).
  4. Trusted proxy — Cloudflare preset / custom CIDR allowlist (consumed by the rate limiter in DB-4).
- Seven AI-callable abilities, all gated by `manage_options`:
  - `settings/get-redaction-list` — read state, no friction.
  - `settings/add-redaction-keyword` — strengthen, no friction.
  - `settings/remove-custom-keyword` — reverse own additions, no friction.
  - `settings/restore-redaction-defaults` — restore baseline, no friction.
  - `settings/remove-default-bucket3-keyword` — weaken Bucket 3 default, **in-chat 1/2 confirmation required**.
  - `settings/exempt-ability-from-bucket3` — per-ability Bucket 3 unlock, **in-chat 1/2 confirmation required**.
  - `settings/unexempt-ability-from-bucket3` — re-lock exemption, no friction.
- One-time confirmation tokens stored as WP transients with 60s TTL, bound to (session, ability, params); single-use; replay-safe.
- All settings writes emit `boundary.master_toggle.changed`, `boundary.redaction_keywords.changed`, `boundary.ability_exemption.changed`, `boundary.confirmation.failed` events through the existing `BoundaryEventEmitter`.
- New option keys: `abilities_mcp_redaction_master_enabled`, `abilities_mcp_redaction_keywords` (Bucket 3 customs), `abilities_mcp_bucket2_keywords` (Bucket 2 customs — DB-2 to read after rebase), `abilities_mcp_bucket3_exemptions`, `abilities_mcp_bucket2_exemptions`, `abilities_mcp_redaction_keywords_removed_defaults`, `abilities_mcp_bucket2_keywords_removed_defaults`, `abilities_mcp_trusted_proxy_enabled`, `abilities_mcp_trusted_proxy_mode`, `abilities_mcp_trusted_proxy_allowlist`.

### Held
- Bucket 2 default-removal, Bucket 2 ability-exemption, master-toggle-off — Admin UI only by design. No ability paths exist for these.
- Released together with DB-1, DB-2, DB-4, DB-5, DB-6 at the Launch Gate.

## [1.2.0] - 2026-03-20

### Added
- `discover-abilities` pagination: `limit` and `offset` parameters for paginated discovery
- `discover-abilities` compact mode: `compact: true` returns only name, category, and tier — reduces response from ~128KB to ~8KB at scale
- GitHub Releases auto-update fallback — users who install from GitHub get update notifications in wp-admin without a FluentCart license

### Changed
- Author branding: Influencentricity → Wicked Evolutions in README
- Store and GitHub install paths documented in README

## [1.1.1] - 2026-03-20

### Added
- GitHub Releases auto-update fallback in plugin updater

## [1.1.0] - 2026-03-17

### Fixed
- `execute-ability` error messages no longer swallowed — handle string error format alongside JSON-RPC array format in ToolsHandler

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
- Deployed with license + permission migration

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
