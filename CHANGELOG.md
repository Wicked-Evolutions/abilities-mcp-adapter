# Changelog

## [Unreleased]

## [1.4.9] - 2026-05-20

### Added

- **FluentPlayer ability category added to the OAuth scope registry (commit `258a21f`).** `src/Auth/OAuth/ScopeRegistry.php` manual scope list now includes `fluent-player`, so FluentPlayer abilities are grantable and executable under OAuth (baseline or via `abilities-mcp reauth <site> --add-scope=…`). Without this entry the v1.4.0 FluentPlayer ability surface would return `insufficient_scope` under OAuth — directly relevant to OAuth clients exercising the FluentPlayer fixes. Additive scope-registry entry; no permission-semantics change to existing scopes (Principle 10). Regression-guarded by `tests/Unit/Auth/OAuth/ScopeRegistryTest.php`.

### Fixed

- **Documented boot entrypoint `mcp-adapter/get-started` is now registered with the default server (Issue [#87](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/87) S3).** `DefaultServerFactory` advertises `server_description.boot_sequence.first_tool = "mcp-adapter/get-started"` (added in the "Boot nudge" change, commit `6b51d24`) but the server's `tools` allowlist was never updated to include it — only `discover-abilities`, `get-ability-info`, `execute-ability`, `batch-execute`. The `GetStartedAbility` registered correctly as a public WordPress ability, but the default MCP server never exposed it, so `tools/call mcp-adapter-get-started` resolved to `-32003 Tool not found` — the documented first boot step was unreachable for every client. `src/Servers/DefaultServerFactory.php` now includes `'mcp-adapter/get-started'` in the `tools` array. Purely additive — exposes an already-registered, already-advertised ability; no schema, name, or permission-semantics change (Principle 10). Regression-guarded by `tests/Unit/Servers/DefaultServerFactoryBootContractTest.php`, which pins the advertised boot `first_tool` and the `tools` allowlist in sync via static source parse so this cannot silently drift again. Full PHPUnit suite green.

- **`McpToolValidator` no longer rejects JSON-spec-correct `stdClass` empty-object schemas (Issue [#125](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/125)).** `McpToolValidator::get_schema_validation_errors()` previously checked `! is_array( $schema['properties'] )` at the root and `! is_array( $property )` at each sub-property, rejecting `new \stdClass()` even though it is the JSON Schema-spec-correct PHP encoding of the empty object literal `{}`. Astra's `Astra_Abstract_Ability::get_final_input_schema()` normalizes no-arg input to `[ 'type' => 'object', 'properties' => new \stdClass() ]` and the top-level `stdClass → array` cast at line 152 is non-recursive, so the nested `stdClass` slipped through and failed validation. The error logged per ability per request — on a site with ~10 Astra no-arg abilities running on a 32MB-`memory_limit` shared host, the resulting log cascade contributed to fatal `Allowed memory size exhausted` PHP errors on legitimate admin endpoints (`/wp-json/wp/v2/users/me`, application-passwords, update-core), captured live on thinknicenow.com 2026-05-20. The fix accepts `stdClass` alongside `array` at both checked lines (root-level `properties` and per-property values). Per Principle 3 (Adapter Is A Projection) and Principle 4 (Schemas Stay WordPress-Native): the adapter validator stops being stricter than the JSON Schema spec for WordPress-native ability registrations. Regression-guarded by two new tests in `tests/Unit/Domain/Tools/McpToolValidatorTest.php` covering both the top-level and the sub-property `stdClass` cases. Closes [#125](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/125).

### Chore

- **`ABILITIES_MCP_ADAPTER_VERSION` constant aligned with plugin header (`'1.4.8'` → `'1.4.9'`).** PR [#123](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/pull/123) bumped the plugin header to `Version: 1.4.9` but missed the matching `define()` in `abilities-mcp-adapter.php`. Same class of drift as the `abilities-for-ai` v1.9.4 constant drift caught at release prep. The constant is used by `Abilities_MCP_Adapter_Plugin_Updater` and any code that reads `ABILITIES_MCP_ADAPTER_VERSION` for diagnostic / update-channel comparison. No functional behavior change beyond reporting the correct version.

## [1.4.8] - 2026-05-12

Hotfix completion of the schema-metadata exemption pattern shipped in [1.4.6] — extends the [#105](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/105) per-ability path to cover the JSON-RPC method-level `tools/list` and `tools/list/all` paths. Marketing-launch-coupled fix: the gap broke AI-client tool catalog loading on any site whose registered abilities include PII-keyword-named properties (`email`, `password`, `phone`, `address`, `ip` and prefix/suffix variants).

### Bug — High (cold-AI contract correctness)

- **#113: `tools/list` and `tools/list/all` no longer corrupt per-tool `inputSchema` / `outputSchema` via PII redaction.** [`ResponseRedactionGate`](src/Infrastructure/Redaction/ResponseRedactionGate.php) now forwards the JSON-RPC method into [`ResponseRedactor`](src/Infrastructure/Redaction/ResponseRedactor.php), and the redactor's schema-metadata exemption — previously gated on the per-ability allowlist established by [#105](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/105) — now also fires for the method-level allowlist `SCHEMA_METADATA_METHODS = ['tools/list', 'tools/list/all']`. The exempt-key check is also widened symmetrically to recognise both the WordPress-REST shape (`input_schema` / `output_schema`, snake_case) and the MCP wire shape (`inputSchema` / `outputSchema`, camelCase) so the same schema-metadata subtree is exempted regardless of which projection emits it. The exemption stays path-aware + schema-aware: only the literal four key names trigger pass-through, and runtime-value redaction on `tools/call` responses is unchanged (verified by negative-control test). Empirically verified against the full helenawillow.com `tools/list` payload (789 tools): zero `[redacted:bucket_3]` sentinels appear in any tool's `inputSchema` or `outputSchema` after the fix. Closes [#113](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/113).

## [1.4.7] - 2026-05-08

Documentation update — README rewrite for OAuth resource server + Connected Bridges + layered-permissions surface coverage. Code unchanged from v1.4.6.

### Documentation

- README rewritten end-to-end:
  - OAuth 2.1 resource server + authorization server endpoints documented (RFC 9728 / 8414 discovery, RFC 7591 DCR, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, scope enforcement at every dispatch path, selected-role enforcement)
  - Connected Bridges admin UI section added — operators manage OAuth client registrations through *WP Admin → Settings → MCP Adapter → Connected Bridges*
  - Settings → Permissions UI section added (the layered-permissions enforcement layer the adapter contributes to)
  - PHP version requirement corrected from 8.0+ to 8.2+ (matches `composer.json` `require.php` and plugin header `Requires PHP`)
  - Boundary event log emit section added — names the v0.1 events the adapter emits (`boundary.session.init`, `boundary.session.terminated`, `boundary.auth.denied`, `boundary.transport.error`, `boundary.rate_limit_hit`)
  - "Usage with the Abilities MCP bridge" section rewritten to reflect recommended install paths (`.mcpb` install for Claude Desktop + `npm install -g @wickedevolutions/abilities-mcp` for terminal MCP clients) — replaces the obsolete `node /path/to/...` example
  - New Notes section: four-layer permissions model, paired ability classes, discovery-vs-authorization distinction (`mcp-adapter-discover-abilities` is registration manifest; `suite/get-status` is authorization gate), selected-consent-role-on-refresh tracked on [#94](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/94)
- Welcome block at top with verbatim *"Welcome, Wordpressnaut"* spaceship paragraph + 3 URL pointers (knowledge.wickedevolutions.com, wickedevolutions.com, abilitiesforai.io)
- Disclaimer block from J at the very top
- Pointer to [PRINCIPLES.md](PRINCIPLES.md) as the *Official WordPress Compatibility Contract* binding all four suite repos
- Existing bottom *Disclaimer* section retired (replaced by J's at top)

Closes [#111](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/111).

## [1.4.6] - 2026-05-07

Alpha Release Gate hotfix bundle — Phase B.1 of the Alpha Release Gate + Issue Reconciliation 2026-05-07 sprint plan. Three coordinated fixes in a single release: PII redaction tightening, schema-printer correctness, and OAuth scope coverage with a drift test that prevents the same class of bug from re-opening.

### Sprint Plan Gate (Principles v1)

- **Registry / source-of-truth impact:** None. No business-domain ability schemas touched. The only registry-adjacent change reads categories the adapter already consumes through `OAuthScopeEnforcer::category_segment()`.
- **Adapter / product-layer impact:** Redaction filter hardened (Errors Stay Compatible boundary still intact; schemas pass through unchanged so the cold-AI contract holds). Schema-metadata exemption is path-aware AND schema-aware so it cannot be used to bypass PII redaction in user data. Scope coverage shifts from manual maintenance to coverage-tested per Principle 9 — the new drift test is the actual fix; manual list maintenance is the drift it prevents.

### Security — High

- **#103: Bucket 3 redaction now covers prefixed email field variants.** [`ResponseRedactor`](src/Infrastructure/Redaction/ResponseRedactor.php) previously matched Bucket 3 keywords by field-name-EQUALS only, so any prefixed/suffixed email-bearing field (`admin_email`, `author_email`, `network_admin_email`, `to_email`, `from_email`, `customer_email`, `billing_email`, `contact_email`, `adminEmail`, `authorEmail`, etc.) slipped through unredacted. The Cold-AI Trinity Test 2026-05-06 (RUN_ID `cold-trinity-2026-05-06T122000Z`) empirically observed this against `multisite/get-site`, `multisite/get-network-settings`, `settings/list`, and `comments/list` — any read-scoped client could trigger the leak. The fix adds a token-based substring matcher: any field whose tokens (split on `_`, `-`, camelCase boundaries) include `email` is redacted as Bucket 3. Scope is intentionally limited to the `email` family; phone/address generalisation is contract-polish work. No broad field-name allowlist exceptions — runtime values named `admin_email`/`author_email`/`customer_email` etc. now redact unconditionally, per the alpha-gate acceptance contract. New regression fixture covers the seven explicit variants the issue calls out plus 22 prefix/suffix/case forms. (#103)

### Bug — High (cold-AI contract correctness)

- **#105: `mcp-adapter/get-ability-info` schemas no longer corrupted by redaction.** The redaction pipeline ran indiscriminately over dispatcher response payloads, so calling `mcp-adapter/get-ability-info users/create` returned `properties.username = ["[redacted:bucket_3]"]` and `properties.email = ["[redacted:bucket_3]"]` instead of the actual JSON Schema describing the ability — silently corrupting the contract every AI client depends on for typed input/output. Fix exempts the `input_schema` and `output_schema` subtrees from redaction when the response originates from one of the dispatcher meta-abilities (`mcp-adapter/get-ability-info`, `mcp-adapter/discover-abilities`). The exemption is path-aware (gated on the producing ability) AND schema-aware (only the literal `input_schema` / `output_schema` keys), so a `meta/list-post-meta` response that happens to contain a key named `input_schema` cannot bypass redaction. Bucket 1 still always redacts; the limit guards (max-depth 64, max-nodes 100,000) still fire on oversized schemas. New regression suite spot-checks `users/create`, `users/update`, `comments/create`, `multisite/create-site`, `users/create-app-password` (all five have Bucket-3-named properties in their schemas). (#105)

### Bug — Medium (operator trust)

- **#101 + #102: OAuth scope coverage now includes every category the live registry surfaces, with a CI drift test pinning the contract.** `OAuthScopeEnforcer::category_segment()` derives `abilities:<category>:<op>` directly from each ability's category, but [`ScopeRegistry::all_scopes()`](src/Auth/OAuth/ScopeRegistry.php) was a manually maintained list — categories that shipped to operators without a corresponding scope produced `Required scope: abilities:<category>:read` even after a full-catalog OAuth grant. Live evidence: `core/get-site-info` on wickedevolutions.com (#101 — category `site`, no `abilities:site:*` scopes registered) and `surecart/get-store-info` on helenawillow.com (#102 — category `surecart-ecommerce`, only the unrelated `surecart` scope group existed). Two-part fix: (1) **add the two missing scope groups** — `site` joins the read-only-only umbrella tier next to `rest`/`site-health`/`diagnostic`/`editorial`, and `surecart-ecommerce` joins the third-party suite tier next to `surecart`/`spectra`/`presto-player`/`astra` (read/write/delete, explicit grant required). (2) **Add `ScopeCoverageDriftTest`** + a captured live-catalog snapshot fixture (`tests/fixtures/live-catalog-snapshot.json`) covering both wickedevolutions multisite and helenawillow single-site. The test fails when a registered category has no scope mapping. Per Principle 9 (Scope Coverage Is Derived Or Coverage-Tested) the test is the actual fix — manual scope-list maintenance is the drift this prevents. The test includes a "no false positive" phase that injects a synthetic uncovered category and asserts the comparator surfaces it, so a green run cannot silently mask a broken check. New `ScopeRegistry::categories_from_registry()` helper and `ScopeRegistry::has_category_coverage()` predicate expose the derived view to the test and to future contributors. (#101, #102)

## [1.4.5] - 2026-05-05

Public Alpha Hardening release — fixes from the GPT 5.5 codebase review (2026-05-04).

### Known limitations

- **Path-style multisite is not yet end-to-end verified.** Subdomain-style multisite is the binding alpha gate. Code paths for path-style subsites are exercised by unit tests, but a full discovery → consent → code → token flow on a path-style network has not been run because no path-style multisite test environment is currently available. Building/locating one is a follow-up infrastructure task; subdomain-style multisite is unaffected.
- **Bridge multisite probe rejection (issue #87) deferred per sprint plan §9 Q6 escape hatch.** PR-5 of the Public Alpha Hardening sprint code-walked the adapter's HTTP transport for #87 and traced the most-likely root cause to **bridge-side**: the bridge's `BearerJsonRpcClient` (used in the `add-site` multisite probe) appears to capture `Mcp-Session-Id` from the `initialize` response but not the `Mcp-Session-Token` HMAC the adapter requires on every subsequent request to prevent session fixation. The adapter's session-validation contract at `HttpSessionValidator::validate_session()` is intentional, well-defended, and matches the documented threat model — when the established MCP runtime session works with the same OAuth token but the one-shot probe fails, the diagnostic narrows to which client implementation echoes the session token and which doesn't. End-to-end fix requires a bridge-side change; tracked in [Wicked-Evolutions/abilities-mcp#54](https://github.com/Wicked-Evolutions/abilities-mcp/issues/54). Empirical reproduction was blocked by [adapter #96](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/96) (separate observable issue: `initialize` returns HTTP 500 with opaque `-32603 Handler error occurred`); diagnostic context appended there. Adapter v1.4.5 ships with no #87 code change.
- **Role downgrade applies on interactive consent only — auto-approve issues full-caps tokens.** The #88 fix persists the operator's selected role on the authorization-code → access-token → refresh-token chain and downgrades effective capabilities at bearer-auth time. **This applies only to tokens minted from the interactive consent screen**, where the operator explicitly chose the role. Token refresh / silent reauth via the auto-approve flow (where the consent form is not rendered because prior_scopes cover the requested set within `silent_cap_days`) does not currently carry the prior consent's role choice — it issues new tokens with no role downgrade applied, and a multi-role operator who selected a downgraded role at the original consent can silently regain full caps on the next refresh. Mitigation: explicit reauth (`bridge reauth --scope=...` on the bridge CLI, or revoke + re-consent) renders a fresh consent screen and resets the chain to the chosen role. Tracked as a follow-up against this milestone in [#94](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/94).

- **`mcp-adapter/batch-execute` overflows tiny batches in cold-AI flows; demoted to post-alpha (Issue [#104](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/104)).** **For batch reads, prefer single-call abilities or smaller per-call params.** Large batches may exceed AI client context windows. Batch-execute compact mode is post-alpha work tracked on [#104](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/104). Single-call ergonomics is the supported alpha path.

### Bug — High

- **#90: Subsite authorize endpoint now dispatches under any path-style prefix.** `AuthorizationServer::intercept_pre_wp_routes()` previously only matched the exact root path `/oauth/authorize`, so a path-style subsite client following its own discovery metadata (which advertises `https://example.com/<prefix>/oauth/authorize`) fell through to WP/404 before consent. The interceptor now matches any path ending in `/oauth/authorize` and threads the leading prefix into `AuthorizeEndpoint::dispatch()` → `handle_get` / `handle_post`. The self-post URL, `wp_login_url()` redirect target, and resource indicator now all carry the same prefix, so the URLs match what the subsite's discovery metadata advertised. Single-site and subdomain-style multisite are unchanged. M-5 (#60) addressed the same gap on the `.well-known/*` discovery paths but did not extend the fix to `/oauth/authorize`; #90 closes the remaining half. (#90)

### Security — Medium

- **#88: Selected consent role is now honored at bearer-auth time.** Previously the consent screen's role-switcher (Appendix H.4.5) validated that the submitted role belonged to the user, then discarded it. Authorization codes and tokens persisted only `user_id`, and bearer auth restored the full WordPress user — a multi-role operator selecting a lower role still granted the bridge their full effective capabilities, silently nullifying the operator's deliberate intent. New `selected_role VARCHAR(64)` column on `kl_oauth_codes`, `kl_oauth_tokens`, and `kl_oauth_refresh_tokens` (db_version 1.1.0 → 1.2.0; `dbDelta` migration runs on `plugins_loaded` after plugin upgrade, idempotent, default `''` preserves today's behavior on in-flight sessions). The selected role rides the auth-code → access-token chain on interactive consent, is inherited through `TokenStore::rotate()` so refresh-token rotation preserves the downgrade, and is surfaced via `OAuthRequestContext::selected_role()` to a new `SelectedRoleEnforcer` registered on `user_has_cap`. The enforcer replaces `$allcaps` with the role's capability map for the OAuth-bound user only — non-OAuth requests, other users on the same request, and tokens with empty `selected_role` (single-role operators or auto-approve flows) all pass through untouched. Unknown role slugs fail closed (zero caps, never silent full caps). **Auto-approve carve-out** — see Known limitations above and [#94](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/94). (#88)
- **#89: Stdio bridge no longer drops requests whose `id` is null.** [`StdioServerBridge::handle_request()`](src/Cli/StdioServerBridge.php) previously extracted the JSON-RPC id via `$request['id'] ?? null`, collapsing two structurally similar but semantically distinct conditions: an absent `id` member (notification — server MUST NOT respond) and an explicit `id: null` value (request with literal null id — server MUST respond, per JSON-RPC 2.0 §4). A spec-compliant client sending `id: null` would hang waiting for a response that the bridge silently suppressed. New static helper `StdioServerBridge::request_id_state()` distinguishes the two via `array_key_exists`; `handle_request()` now suppresses the response only when the id member was absent. Brings the stdio transport to parity with `HttpRequestHandler::process_single_message()` which already used `array_key_exists` correctly. (#89)
- **#91: OAuth rate limits no longer trust spoofable forwarded IPs.** `oauth_client_ip()` (the keying function for DCR and revoke rate limiters) previously honored `X-Forwarded-For` whenever `WP_OAUTH_TRUST_FORWARDED_HOST` was defined, with no `REMOTE_ADDR` allowlist check. A caller from any source could rotate spoofed forwarded values to bucket each request into a unique rate-limit slot, bypassing the cap. The helper now delegates to `TrustedProxyResolver::resolve()`, which gates forwarded headers on `REMOTE_ADDR` being in the trusted-proxy allowlist (Cloudflare CIDRs or operator-configured custom list via the Safety Settings UI, the existing surface from DB-4). The outer `WP_OAUTH_TRUST_FORWARDED_HOST` constant is preserved as a layered safety gate — operators who never opted in see zero behavior change; operators who opted in but never configured trusted-proxy mode now silently get the safe path (`REMOTE_ADDR`), which is the bypass closure. Real proxy deployments with a configured allowlist continue to work. (#91)

## [1.4.4] - 2026-05-02

### Test infra
- **#27: Rate-limit burst harness shipped.** New CLI tool `bin/rate-limit-burst.php` and `RateLimit\BurstHarness` helper class — session-aware harness that exercises the live `/wp-json/mcp/mcp-adapter-default-server` endpoint past its IP and initialize windows and verifies the wire response (429 + Retry-After + boundary log entry) matches the limiter contract. Pairs with `RateLimiter`'s 33 unit cases, which pin the in-memory math; this harness pins the wire behavior. Two cases (`threshold-trip`, `initialize-window`) automated; the multi-source per-IP separation and trusted-proxy header trust matrix are documented in the script header for operator-run coverage. 15 unit tests cover header parsing, session merge (defensive vs future per-request token rotation), and result classification. (#27)

### UX / tech-debt
- **L-3: DCR registration response now includes `sensitive_scopes_requested`.** Audit (2026-04-27) flagged that the Connected Bridges admin UI conflated "client requested sensitive scopes at DCR" with "client has been consented to sensitive scopes" — a misleading audit signal because sensitive scopes still require explicit interactive consent at `/oauth/authorize` per H.3.4. New `sensitive_scopes_requested` field on the POST `/oauth/register` response (RFC 7591 extension) lists the subset of valid requested scopes that are sensitive, so bridges and the Connected Bridges UI can show "X sensitive scopes requested — will require explicit consent" without inventing the classification client-side. Storage unchanged (sensitive scopes still survive into the DCR record; gating remains at consent time). New `RegisterEndpoint::classify_scopes()` helper makes the valid/sensitive split unit-testable. (#68)

### Bug — High
- **Fluent suite scopes added to `ScopeRegistry` — every Fluent ability under OAuth now grantable.** The OAuth scope catalog had per-module entries for `presto-player`, `surecart`, `astra`, `spectra`, and the WordPress core categories, but **none for the Fluent suite**. Every Fluent ability (FluentCRM, Fluent Community, Fluent Forms, Fluent Support, Fluent Boards, FluentBooking, FluentSMTP, FluentAuth, Fluent Snippets, Fluent Messaging, FluentCart, FluentAffiliate, plus cross-module `fluent`) failed at execute time with `insufficient_scope`, and `bridge reauth --scope=...` rejected upfront with "Unknown scope(s)". Implemented Option B (per-module scopes, matching the existing third-party suite pattern): 12 Fluent module categories × {read, write, delete} = 36 new scopes, plus `abilities:fluent:{read, write, delete}` for cross-module abilities (39 scopes total). No abilities-for-fluent-plugins changes required — `OAuthScopeEnforcer` derives `abilities:<category>:<op>` from `WP_Ability::get_category()` and the abilities-for-fluent-plugins Registrar already auto-sets per-module categories. (#74)

### Tech-debt
- **AuthHeaderProbe namespace gate cleaned up (H.2.6 diagnostic now actually fires).** `AuthorizationServer::authenticate_bearer` was matching both `/wp-json/mcp/` and the stale `/wp-json/abilities-mcp-adapter/` namespace before recording an observation. The latter is left over from a pre-rename branch — no REST routes are registered there, so the probe was silently dead on requests that hit it (and harmlessly recording-on-noise on requests that didn't, which means the rolling counter never reflected real traffic). Dropped the dead OR branch; probe now records only on `/wp-json/mcp/` traffic, restoring the H.2.6 diagnostic. (#53)
- **MCP route lifted to a single source of truth.** Previously the path `mcp/mcp-adapter-default-server` was hard-coded across `AuthorizationServer`, `AuthorizeEndpoint`, `DiscoveryEndpoints`, and `helpers.php` (six callsites across four files). Drift between callsites would silently narrow Bearer auth or break resource validation. New `McpResourcePath` value class exposes `REST_NAMESPACE`, `ROUTE`, `PATH` (no leading slash, for `rest_url()`), and `LEADING_SLASH_PATH` (for REQUEST_URI / rest_route compares). All production callsites now consume the constants; a future rename touches one file. Behavior-preserving refactor — all 855 existing tests stay green; 4 new tests pin the constant values. (#54)

### Performance / tech-debt
- **L-2: `TokenStore::touch()` no longer issues a synchronous `UPDATE` per request.** Previously every authenticated MCP request blocked on a `wpdb->update` of `last_used_at` on the access-token table — a hot row under burst load. `touch()` now stamps a per-request in-memory buffer keyed by `token_hash` and registers a `register_shutdown_function` flush on first use. Multiple touches for the same token within one request coalesce into one UPDATE; distinct tokens flush as N UPDATEs after the response is sent. Cross-request batching (transient + cron flush, issue body's Option A) is intentionally not introduced — the simpler shutdown-flush refactor is sufficient at current scale and leaves Option A as a future move without changing the `touch()` API. (#67)

### Security — Medium
- **M-3: `OAuthRequestContext::has_scope()` renamed to `oauth_has_scope()` with strict-false default on non-OAuth requests.** Audit (2026-04-27) flagged the previous "non-OAuth → return true so WP caps govern" default as trivially fail-open if a future caller used the function as the sole authorization gate. The function had no production callers in `src/` (the actual scope enforcer lives in `OAuthScopeEnforcer::check()` / `check_scope()` and consults `is_oauth_request()` + `granted_scopes()` directly), so the rename + semantic flip carries no migration cost. Callers must now handle the non-OAuth path explicitly (typically via `current_user_can( ... )` after `is_oauth_request()`). Direct `in_array` semantics retained — sensitive scopes are still NEVER implied by umbrella grants; for umbrella-aware non-sensitive scope expansion, route through `OAuthScopeEnforcer::check_scope()`. Spec amendment to `DESIGN — OAuth 2.1 in the Adapter 2026-04-27.md` flagged for the CTO during PR review. (#64)
- **M-8: `LastConsentLookup::timestamp_for()` is now explicitly fail-closed.** Audit (2026-04-27) flagged the unhandled-throw path: a third-party `pre_option_*` / `option_*` filter that throws would bubble to a 500 instead of routing the operator to consent. Verified the existing flow was already implicitly fail-closed (null return → `ConsentDecisionEvaluator` branch 1 → `RENDER_FULL` with reason `first_authorization`). Locked the contract: any `\Throwable` from the option backend now returns null, which is strictly safer than a 500. `days_since()` inherits the same protection. (#65)
- **M-9: `AuthorizationCodeStore::store()` now checks `$wpdb->insert` return.** Previously a `code_hash` UNIQUE-key collision (probability ~2^-128) or any other DB-side insert failure was silently swallowed; the bridge received the auth code in the redirect URL but `/oauth/token` failed with `invalid_grant` and no log signal. `store()` now returns `bool`, emits `boundary.oauth_code_insert_failed` with `client_id` + `wpdb->last_error` on failure, and `AuthorizeEndpoint::mint_code_and_redirect` redirects with `error=server_error` instead of redirecting with an unredeemable code. (#66)

## [1.4.3] - 2026-04-28

OAuth 2.1 second-pass hardening release. Five additional findings from external security review fixed in two PRs (#71, #72).

### Security — Medium
- **M-2: `OAuthRequestContext` reset only fired on `rest_api_init`.** PHP-FPM workers handling REST + non-REST requests could retain stale singleton state across requests. Reset is now also wired to `init` priority 0; both hooks remain for belt-and-braces. (#71)
- **M-4: `esc_url_raw($params['redirect_uri'])` mutated the value before `hash_equals` in `TokenEndpoint::handle_auth_code`.** Round-trip mutation defeats timing-safe semantics and could lock out legitimate clients on URIs with characters `esc_url_raw` re-encodes. Now `trim()` only — matches `AuthorizeRequestValidator::str()` storage-side normalization exactly. (#71)
- **M-6: REST routes `/wp-json/mcp/oauth/{register,token,revoke}` bypassed `OAuthHostAllowlist`.** Pre-WP routes (`/oauth/authorize`, `/.well-known/*`) were gated; REST routes weren't. New `rest_host_allowlist_gate()` wired as `permission_callback` on all six REST routes — unknown hosts now get `WP_Error 404` + `boundary.oauth_host_rejected` event, parity with the pre-WP path. (#71)
- **H-9: Loopback redirect_uri query-string compare was order-sensitive and not RFC 8252 §7.3 compliant.** `?foo=1&bar=2` and `?bar=2&foo=1` would not match; percent-encoding differences and trailing-`?` would also reject equivalent URIs. New `query_normalize()` helper (`parse_str` → `ksort` → `http_build_query(PHP_QUERY_RFC3986)`) makes loopback query compare order-and-encoding-stable. Fragments now rejected on both sides per RFC 6749 §3.1.2. Path strict compare retained (most native HTTP servers route `/cb` and `/cb/` differently). (#72)

### Security — Low
- **L-1: Bearer Authorization strings beyond `Bearer ` prefix not trimmed.** `Authorization: Bearer  TOKEN` (two spaces from a misbehaving proxy) hashed as ` TOKEN` and silently failed validation. Now `trim()`'d. (#71)

### Internal
- Test count: 844 (+34 since 1.4.2). PHP CI matrix unchanged: 8.2, 8.3.

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
