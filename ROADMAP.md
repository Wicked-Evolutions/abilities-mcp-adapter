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
| SessionManager non-atomic lock (adapter#2) | Medium | Transient-based check-before-set has TOCTOU race. Retry logic mitigates. GET_LOCK patch deployed server-side but NOT in repo. |
| Tool refresh after plugin install (adapter#1) | Low | STDIO-only issue. HTTP transport unaffected. Won't-fix candidate — tools are fetched fresh each request, no cache to invalidate. |

## Gaps

| Gap | Priority | Notes |
|-----|----------|-------|
| GET_LOCK patch not in repo | Medium | MySQL `GET_LOCK()` session locking deployed on servers but repo still has transient-based approach. Anyone installing from GitHub gets the weaker locking. |
| No automated tests | Medium | 282 tests existed in upstream fork but plugin-level tests missing. |
| Inactive adapter copies on servers | Low | `hostinger-ai-assistant` on WE, `wp-mcp-adapter` on Helena. Risk of confusion if reactivated. |
| Orphaned `mcp_session_lock_*` transients | Low | Old locking mechanism leftovers in wp_options. Cosmetic. |
| Upstream governance undefined | Low | No process for tracking/updating `wordpress/mcp-adapter` releases. |

## Not Started

| Item | Priority | Notes |
|------|----------|-------|
| Document upstream update process | Medium | When `wordpress/mcp-adapter` ships new versions, how to update without losing patches. |
| Basic validation/smoke test | Medium | No automated tests exist in plugin. |
| `.github/ISSUE_TEMPLATE/` | Low | If repo goes public. |
| STDIO tool refresh fix | Low | 3-file fix designed by Lane D. Only matters for STDIO users. |

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

- ~~Dead constants `LOCK_KEY_PREFIX`, `LOCK_MAX_ATTEMPTS`~~ — Actively used in transient-based locking. NOT dead code.
- ~~adapter#3 (cross-ref #5)~~ — Parent issue resolved. Close this issue.
