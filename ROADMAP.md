# ROADMAP — MCP Adapter for WordPress

> Source of truth for product development state. Obsidian roadmap references this file.
> Part of the Wicked Evolutions Trinity AI Suite for WordPress.

**Current version:** v1.0.2-alpha
**Health:** Strong — fully decoupled, PSR-4 namespace, standalone codebase

---

## Open Bugs

| Bug | Priority | Notes |
|-----|----------|-------|
| ~~`McpAdapter::VERSION` constant mismatch~~ | ~~Low~~ | **FIXED** — constant updated to `1.0.2-alpha`. |
| ~~SessionManager non-atomic lock (adapter#2)~~ | ~~Medium~~ | **FIXED** — `acquire_lock()` now uses MySQL `GET_LOCK()` for true atomicity, with transient fallback. |
| ~~Tool refresh after plugin install (adapter#1)~~ | ~~Low~~ | **WON'T-FIX** — STDIO-only issue. HTTP transport (all production use) fetches tools fresh each request. No cache to invalidate. |

## Gaps

| Gap | Priority | Notes |
|-----|----------|-------|
| ~~GET_LOCK patch not in repo~~ | ~~Medium~~ | **FIXED** — `GET_LOCK()` now in repo. Transient fallback retained for edge cases. |
| No automated tests | Medium | 282 tests existed in upstream fork but plugin-level tests missing. |
| ~~Inactive adapter copies on servers~~ | ~~Low~~ | **RESOLVED** — neither `hostinger-ai-assistant` nor `wp-mcp-adapter` exist on either server. Already removed. |
| ~~Orphaned `mcp_session_lock_*` transients~~ | ~~Low~~ | **RESOLVED** — zero transients found on WE or Helena. 5s TTL = already expired. GET_LOCK switch means no new ones created. |
| ~~Upstream governance undefined~~ | ~~Low~~ | **DEFERRED** — `wordpress/mcp-adapter` hasn't shipped a release yet. Revisit when upstream publishes. Tracked in "Not Started" as documentation task. |

## Not Started

| Item | Priority | Notes |
|------|----------|-------|
| Document upstream update process | Medium | When `wordpress/mcp-adapter` ships new versions, how to update without losing patches. |
| Basic validation/smoke test | Medium | No automated tests exist in plugin. |
| `.github/ISSUE_TEMPLATE/` | Low | If repo goes public. |
| ~~STDIO tool refresh fix~~ | ~~Low~~ | **WON'T-FIX** — STDIO deprecated, HTTP is production transport. Design archived in CTO-BRIEF 2026-03-02 if ever needed. |

## Recently Completed

| Item | Version | Date |
|------|---------|------|
| GPL-2.0 compliance (LICENSE, headers, copyright) | v1.0.2-alpha | 2026-03-11 |
| Broadened MCP client compatibility language | — | 2026-03-11 |
| Fix `ability_missing_input_schema` for no-arg abilities | v1.0.2-alpha | 2026-03-10 |
| Fix `empty()` null conversion blocking ability execution | v1.0.2-alpha | 2026-03-10 |
| Deploy v1.0.2-alpha to WE + Helena | — | 2026-03-10 |
| PSR-4 autoloading + `WickedEvolutions\McpAdapter` namespace | v1.0.0-alpha | 2026-03-08 |
| Batch execute tool (max 20 per request) | v1.0.0-alpha | 2026-03-08 |
| Admin settings page (per-ability enable/disable) | v1.0.0-alpha | 2026-03-08 |
| Permission metadata in MCP annotations | v1.0.0-alpha | 2026-03-08 |
| HTTP transport with session management | v1.0.0-alpha | 2026-03-08 |
| Fix batch-execute (server discovery, error isolation, wire format) | v1.0.1-alpha | 2026-03-09 |
| Fix get-ability-info `show_in_rest` | v1.0.1-alpha | 2026-03-09 |

## Resolved Bugs

| Bug | Fixed in | Notes |
|-----|----------|-------|
| `ExecuteAbilityAbility` `empty()` null conversion | v1.0.2-alpha | `empty($input['parameters'])` converted `[]` to `null`. Fix: `?? array()` |
| `ability_missing_input_schema` for no-arg abilities | v1.0.2-alpha | Pass `null` instead of `$parameters` when ability has no input_schema |
| `get-ability-info` self-gating | v1.0.1-alpha | `show_in_rest: true` was missing |
| BatchExecute hardcoded server name | v1.0.1-alpha | Uses `get_servers()` + `reset()` |
| BatchExecute no error isolation | v1.0.1-alpha | Per-item try/catch |
| BatchExecute wrong wire format | v1.0.1-alpha | `{error}` → `isError: true` |
| MCP tools not registering (GitHub #5) | — | Bridge-side fix. Annotations + protocol version. |

## False Alarms (verified 2026-03-11)

- ~~Dead constants `LOCK_KEY_PREFIX`, `LOCK_MAX_ATTEMPTS`~~ — `LOCK_KEY_PREFIX` actively used. `LOCK_MAX_ATTEMPTS` removed (inlined in transient fallback).
- ~~adapter#3 (cross-ref #5)~~ — Parent issue resolved. Close this issue.
