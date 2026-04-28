# Changelog

## [1.4.2] - 2026-04-28

OAuth 2.1 hardening release. Eight findings from external security review fixed in eight sequential PRs (#52, #55, #56, #57, #58, #59, #60, #61).

### Security — Critical
- **C-1: Bearer auth global-session leak.** `authenticate_bearer()` previously fired on every WP REST request; a Bearer token issued for `/wp-json/mcp/...` could authenticate the holder against any other REST endpoint on the site. Now narrowed to MCP resource paths only — non-MCP routes no-op. (#52)
- **C-2: Refresh idempotent retry returned `invalid_grant`.** The grace-window retry path stored a hash, then tried to return plaintext, hit the contradiction, and emitted `invalid_grant`. Bridge retry-on-network-blip — the very scenario H.2.1's grace was designed for — evicted operators to reauth. Redesigned with encrypt-at-rest: rotation stores the new plaintext pair as AES-256-GCM ciphertext under an HKDF-SHA256 key derived from the *old* refresh token's plaintext + `AUTH_KEY`. Retry within grace decrypts using the supplied old plaintext, returns the original pair, and one-shot wipes the blob. Retry outside grace revokes the family. New schema columns `replay_blob` and `replay_blob_iv` on `kl_oauth_refresh_tokens`; `db_version` 1.0.0 → 1.1.0 via `dbDelta` (idempotent). (#61)
- **C-3: 401 with no `WWW-Authenticate` challenge.** Unauthenticated requests to MCP resource paths returned a plain 401 with no challenge header, breaking RFC 6750 §3 discovery. Bare-form `WWW-Authenticate: Bearer realm=..., resource_metadata=...` (no `error` param) now scheduled on every MCP-path 401 with no `Authorization` header. (#56)

### Security — High
- **H-1: Distinguishable error_description for revoked vs expired/missing tokens.** A polling attacker could distinguish revocation from natural expiry by reading `error_description`. Normalized to identical text. (#56)
- **H-2: `/oauth/revoke` accepted unauthenticated requests from any caller.** Now requires `client_id` that hash-equals the stored value (RFC 7009 §2.1 public-client proof of possession). Revocation now cascades — refresh revoke → `revoke_family`; access revoke → paired refresh tokens marked revoked. New `TokenStore::find_token_meta()` helper. (#56)
- **H-3: No cleanup of expired/unused records.** New `OAuthCleanup` class with daily `abilities_oauth_cleanup_unused_clients` cron pass. All four `kl_oauth_*` tables cleaned in BATCH=500 loops. 50,000-row alert persisted to an option + admin notice. Schedule wired at activation, `init` priority 25 (survives plugin updates), and deactivation. (#57)
- **H-4: Non-atomic per-IP rate-limit counter (race).** RateLimiter primitives replaced: `wp_cache_add` + `wp_cache_incr` when an external object cache is present (atomic on Memcached/Redis); `get_site_transient` / `set_site_transient` fallback (network-wide on multisite — all subsites share one budget). Applied to both DCR and revoke rate limiters. (#57)
- **H-5: Scope enforcer not wired at every dispatch path.** `OAuthScopeEnforcer::check()` was only called at one tools handler; meta-tool, prompts/get, and batch-execute dispatchers bypassed it. Wired at `ToolsHandler`, `ResourcesHandler`, `PromptsHandler`, and `ExecuteAbilityAbility` per-underlying dispatch. Closes scope-bypass issues #39, #40, #42. Builder-based prompts default to `abilities:mcp-adapter:read`; `destructive=true` dispatchers can carry an explicit `permission=read` override. (#55)
- **H-6: Token response shape and scope semantics.** Token responses now include `token_type: 'Bearer'` (RFC 6749 §5.1). Scope returned to clients is the stored umbrella-expanded set verbatim, not the originally-requested string — gives clients an unambiguous picture of what the token actually covers. (#58)

### Security — Medium
- **M-5: Path-style multisite discovery routing.** `intercept_pre_wp_routes()` now matches `.well-known/...` and `/oauth/authorize` with `str_starts_with` and extracts the trailing subsite path prefix. `DiscoveryEndpoints` issuer URLs include the prefix so every URL in the discovery documents points to the correct subsite issuer. Enables OAuth on subdirectory multisite setups. (#60)
- **M-7: `esc_attr()` HTML-encoded `WWW-Authenticate` header values.** Header values must not contain quotes; the correct fix is to strip them, not HTML-encode them to `&quot;`. (#56)

### Fixed — non-security
- **`family_id` rotation chain broken.** `TokenStore::rotate()` called `issue()` which generated a fresh `family_id` for every rotation, so `revoke_family()` only covered the most recent leg of a chain. `issue()` gains an optional seventh parameter; `rotate()` passes the existing `family_id` through. Every token in a rotation chain now shares one family ID. (#59)

### Internal
- Schema migration `db_version 1.0.0 → 1.1.0` adds nullable `replay_blob` (LONGBLOB) and `replay_blob_iv` (VARCHAR(32)) columns to `kl_oauth_refresh_tokens`. Existing rows get NULL, fall through to `invalid_grant` on grace retry. No backfill required.
- Test count: 810 (+82 since 1.4.1). PHP CI matrix unchanged: 8.2, 8.3.

## [1.4.1] - 2026-04-26

### Fixed
- **Text-channel PII leak in `tools/call` responses** (`f0da80f`). MCP responses include both `structuredContent` (object) and `content[0].text` (JSON-serialized string of the same data). The recursive redactor matched field names but never traversed into JSON-encoded strings, so emails redacted in `structuredContent` leaked raw in `content[0].text`. Bridge clients (Claude Desktop, Cursor) read the text channel — bug was visible to every operator using the bridge. Fixed by `ResponseRedactionGate::reconcile_tool_channels()`, which regenerates `content[i].text` from the redacted `structuredContent` after the recursive pass. Single-channel text responses also get a JSON decode → redact → re-encode pass; image responses (`content[i].type === 'image'`) untouched. Caught in post-release verification by external review.

## [1.4.0] - 2026-04-26

Public alpha hardening release. Five integrated dev briefs landing as one canonical merge from PR #26. Companion releases: [abilities-for-ai v1.9.0](https://github.com/Wicked-Evolutions/abilities-for-ai/releases/tag/v1.9.0), [abilities-mcp v1.4.0](https://github.com/Wicked-Evolutions/abilities-mcp/releases/tag/v1.4.0).

### Added — Response redaction filter (DB-2)
- Three-bucket redaction at the `/mcp` response boundary. Bucket 1 (secrets — passwords, API keys, tokens, salts, password hash patterns, known API-key value prefixes, Luhn-checked card numbers) always filtered, cannot be disabled. Bucket 2 (payment / regulated identifiers — `card_number`, `cvv`, `ssn`, `tax_id`, etc.) default-on, configurable via Admin UI only. Bucket 3 (contact PII / access labels — `email`, `phone`, `address`, `user_login`, `ip`, `public_key`, etc.) default-on, configurable via Admin UI or AI.
- Type-aware redaction markers preserve response schema. Scalar string fields → `"[redacted:bucket_N]"`; object fields → `{"redacted": true, "reason": "bucket_N"}`; array fields → single-element array preserving shape. Schema-validating clients see the type they expect.
- Recursive traversal with depth limit 64 and node limit 100,000 to prevent DoS via crafted responses.
- Per-ability exemptions for Bucket 3 unlock contact PII visibility on specific abilities (e.g. CRM workflows). Bucket 2 exemptions exist but are Admin-UI only — never weakenable through chat.
- Meta-tool unwrap: when a tool call goes through `mcp-adapter-execute-ability`, the redactor reads the inner `arguments['ability_name']` for exemption lookup, with a dash-form-to-slash-form translator that resolves MCP wire names (`fluent-cart-list-customers`) back to canonical ability names (`fluent-cart/list-customers`) via `wp_get_abilities()`.
- New filter hook `mcp_adapter_redaction_keywords` for runtime keyword list overrides.

### Added — Safety Settings UI + AI-callable settings abilities (DB-3)
- New admin page **Settings → MCP Safety** with master toggle (off requires checkbox confirmation), bucket keyword list editor (Bucket 1 read-only; Bucket 2 with per-default warning; Bucket 3 with per-default no warning; restore defaults), per-ability exemptions (two columns — Bucket 3 left, Bucket 2 right with confirm-on-add warning), trusted-proxy configuration (Cloudflare preset / custom CIDR allowlist).
- Seven AI-callable abilities, all gated by `manage_options`: `settings/get-redaction-list`, `settings/add-redaction-keyword`, `settings/remove-custom-keyword`, `settings/restore-redaction-defaults`, `settings/remove-default-bucket3-keyword` (in-chat 1/2 confirmation required), `settings/exempt-ability-from-bucket3` (in-chat 1/2 confirmation required), `settings/unexempt-ability-from-bucket3`.
- One-time confirmation tokens stored as WP transients with 60s TTL, bound to `(session, ability, params)`. Single-use; replay-safe.
- Bucket 2 keywords reject upfront when passed to `settings/remove-default-bucket3-keyword` — operators get a structured error pointing to WP Admin instead of a misleading confirmation prompt.
- Settings writes emit `boundary.master_toggle.changed`, `boundary.redaction_keywords.changed`, `boundary.ability_exemption.changed`, `boundary.confirmation.failed` events through the existing `BoundaryEventEmitter`.
- New option keys: `abilities_mcp_redaction_master_enabled`, `abilities_mcp_redaction_keywords`, `abilities_mcp_bucket2_keywords`, `abilities_mcp_bucket3_exemptions`, `abilities_mcp_bucket2_exemptions`, `abilities_mcp_redaction_keywords_removed_defaults`, `abilities_mcp_bucket2_keywords_removed_defaults`, `abilities_mcp_trusted_proxy_enabled`, `abilities_mcp_trusted_proxy_mode`, `abilities_mcp_trusted_proxy_allowlist`.

### Added — Rate limiter at /mcp boundary (DB-4)
- Per-IP + per-user sliding-window rate limiting before handler dispatch. Default 60 requests/minute per dimension; configurable.
- Separate 30/min/IP window for `initialize` handshake — prevents authenticated clients from looping new sessions while leaving the post-auth limiter scoped to actual tool work.
- Trusted-proxy IP detection rules: `REMOTE_ADDR` is the only trusted source by default; `X-Forwarded-For`, `CF-Connecting-IP`, `X-Real-IP`, `True-Client-IP` honored only when the operator enables a trusted-proxy preset. Cloudflare preset auto-fetches Cloudflare's published IP ranges and trusts the header only when the request originates from one. Custom-allowlist preset accepts an operator-supplied CIDR list. Without these rules, the limiter would either be useless behind Cloudflare or trivially spoofable.
- 429 responses include `Retry-After` header. Rate-limit hits emit `boundary.rate_limit_hit` events with truncated IPs and dimension/method tags.

### Added — Origin allowlist + CORS + minimal SSE stub (DB-5)
- Origin header validation as defense-in-depth against DNS rebinding. Same-host and configurable per-origin allowlist.
- CORS scoped to MCP routes only — `rest_pre_serve_request` hook conditionally suppresses WordPress core's `rest_send_cors_headers()` for MCP namespace requests, leaving every other REST route's CORS behavior untouched.
- Auth-denied event tags carry truncated IPs (/24 for IPv4, /48 for IPv6) and enum reason codes (no free-form exception text leaks through hooks).
- Minimal Server-Sent Events stub on `GET /mcp` — `text/event-stream` with bounded heartbeat. Replaces the previous "not yet implemented" 405 stub. Future server-initiated events can extend this surface.

### Added — Boundary event sanitization
- `BoundaryEventEmitter` hashes incoming `api_key` to `api_key_hash` before firing the typed handler and the `mcp_adapter_boundary_event` action hook. Raw API keys never reach listeners. `public_key` moved out of always-on Bucket 1 and into configurable Bucket 3 (public keys are intentionally shareable; SSH host keys, JWT verification keys, OAuth public keys all qualify).

### Changed
- Plugin version bumped to 1.4.0.

## [1.3.0] - 2026-04-26

### Added — Boundary event prerequisite
- `BoundaryEventEmitter` and `mcp_adapter_register_observability` action hook (`a43167a`). Adapter-side groundwork for the Launch Gate sprint — emits sanitized boundary events through both a typed `McpObservabilityHandlerInterface` and a third-party-friendly action hook. Initial sanitization pass; the full hashing of `api_key` lands in v1.4.0's security pass.

### Fixed
- CI infrastructure: `composer.lock` pinned to `doctrine/instantiator <2.1.0` (`e06a658`) to restore the PHP 8.0–8.3 test matrix. The transitive dependency had been auto-updated to a 2.1.0 release that requires PHP 8.4 — incompatible with our supported floor. Affects CI green only; runtime behavior unchanged.

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
