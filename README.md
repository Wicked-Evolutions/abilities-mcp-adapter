# Abilities MCP Adapter

> **A word from J, the director of this creation.**
>
> Everything you see here is built by a single human who does not read or write code and is written by AI. Everything is in constant motion and by observing that movement we create the illusion of being still. Change happens at any given moment. It is simply a law of evolution. Stillness is an act of conscious awareness, not a reality of life.

## Welcome, Wordpressnaut

Here is the spaceship, now you'll have to learn how to fly and please do remember, humans make mistakes, humans created AI so AI makes mistakes. Learning to fly is your job and to do that you'll need structure, systems, checklists, principles and understanding you stand before a magical leap of a steep and wonderful learning curve. Be patient and do backup things.

→ Knowledge layer (deeper traversal): [https://knowledge.wickedevolutions.com](https://knowledge.wickedevolutions.com)
→ [https://wickedevolutions.com](https://wickedevolutions.com)
→ [https://abilitiesforai.io](https://abilitiesforai.io)

Our development aim is the *Official WordPress Compatibility Contract* — see [PRINCIPLES.md](PRINCIPLES.md) for the full binding principles across the four-repo suite.

---

Converts WordPress abilities into MCP (Model Context Protocol) tools, resources, and prompts. Any ability registered via `wp_register_ability()` automatically becomes accessible to AI agents — zero configuration required. Runs the OAuth 2.1 resource server + authorization server for the suite, ships the Settings → Permissions UI that gates per-module execution, and contributes the runtime layer of the four-layer permissions model.

## Features

### Discovery & execution

- **Automatic discovery** — abilities with `show_in_rest` or `mcp.public` metadata become MCP tools, regardless of which plugin registered them
- **Built-in MCP tools** — discover abilities, get info, execute single, execute batch
- **Permission metadata** — abilities carry `permission` (read/write/delete) and `enabled` state in MCP annotations
- **MCP annotations** — readonly, destructive, idempotent hints flow through to tool definitions
- **Schema transformation** — JSON Schema to MCP-compatible format with automatic wrapping
- **Error mapping** — `WP_Error` objects map cleanly to MCP error codes
- **HTTP transport** — REST API endpoint with session management, plus minimal Server-Sent Events stub

### OAuth 2.1 resource server + authorization server (since v1.4.0)

- **RFC 9728 + RFC 8414 discovery** — `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server` advertise the OAuth surface; HTTPS-only, `.well-known/*` refuses redirects
- **RFC 7591 Dynamic Client Registration** — `/oauth/register` mints a fresh client_id per bridge; rate-limited per-IP with atomic counters (Memcached/Redis when available, transient fallback)
- **`/oauth/authorize`** — authorization endpoint with PKCE S256 verifier validation, role-selector consent screen, host allowlist gate, trusted-proxy-aware rate limiting; supports both root and path-style WordPress installs
- **`/oauth/token`** — token endpoint with auth-code grant + refresh-token grant; refresh rotation uses encrypt-at-rest grace-window retry (HKDF-SHA256 key derived from old refresh + `AUTH_KEY`)
- **`/oauth/revoke`** — RFC 7009 revocation with `client_id` proof of possession; cascades through the refresh-token family
- **Scope enforcement (`OAuthScopeEnforcer`)** — wired at every dispatch path (`ToolsHandler`, `ResourcesHandler`, `PromptsHandler`, `ExecuteAbilityAbility`); scopes are derived from registered ability categories per Principle 9 (Scope Coverage Is Derived Or Coverage-Tested), with a CI drift test pinning the contract
- **Selected role enforcement** — operator's selected role at consent time persists through the auth-code → access-token → refresh-token chain; `SelectedRoleEnforcer` replaces `$allcaps` for OAuth-bound users only

### Connected Bridges admin UI

Operators manage OAuth client registrations through **WP Admin → Settings → MCP Adapter → Connected Bridges**:

- One row per registered bridge with `client_id`, redirect URI, requested + sensitive scopes, last activity, and revoke action
- DCR registration response carries `sensitive_scopes_requested` so the admin UI can show *"X sensitive scopes requested — will require explicit consent"* without inventing the classification client-side
- AuthHeaderProbe diagnostic surfaces whether the `Authorization` header survives end-to-end against MCP-resource paths

### Settings → Permissions UI (the layered-permissions enforcement layer)

Operators control which modules and which tiers (read/write/delete) the bridge can execute through:

- **WP Admin → Settings → MCP Abilities** — per-ability enable/disable controls with permission tier overrides
- **WP Admin → Settings → MCP Safety** — master redaction toggle (with warning checkbox), keyword editor per bucket, per-ability exemption list, trusted-proxy configuration

Per-module read/write/delete state is the *Abilities for AI module* layer in the [four-layer permissions model](#four-layer-permissions-model). When an ability is denied at this layer, the runtime returns `[ability_disabled]` with the module name and the WP Admin path to fix it.

### Safety surface (v1.4.x)

- **Three-bucket response redaction** — secrets always filtered (passwords, API keys, tokens, hashes); payment / regulated identifiers and contact PII filtered by default with operator-controlled overrides; type-aware markers preserve schema shape; prefixed/suffixed email field variants covered as of v1.4.6 (#103)
- **Per-ability exemptions** — operators unlock contact PII visibility on specific abilities (e.g. CRM workflows that legitimately need email) without weakening defaults globally; weakening default safety requires in-chat 1/2 confirmation; Bucket 2 (payment/regulated) cannot be weakened through chat at any granularity
- **Origin allowlist + scoped CORS** — defense-in-depth against DNS rebinding; CORS scoped to MCP routes only, no global REST API side effects
- **Rate limiting at /mcp boundary** — per-IP and per-user windows, with Cloudflare and custom-allowlist trusted-proxy presets
- **Boundary event log** — structured events for session lifecycle, auth denials, transport errors, rate-limit hits, and settings audit changes (consumed by [Abilities for AI](https://github.com/Wicked-Evolutions/abilities-for-ai)'s `kl_boundary` writer when present)
- **Sanitized event hooks** — third-party listeners receive sanitized metadata only; raw API keys are hashed before any listener fires
- **AI-callable safety configuration** — operators can ask their AI to read or strengthen safety settings via the dedicated `settings/*` ability namespace below

## Requirements

- WordPress 6.9+ (Abilities API)
- PHP 8.2+

## Installation

### From our store

Download from [community.wickedevolutions.com/item/abilities-mcp-adapter/](https://community.wickedevolutions.com/item/abilities-mcp-adapter/), then upload via **Plugins → Add New → Upload Plugin**.

### From GitHub

```bash
cd wp-content/plugins/
git clone https://github.com/Wicked-Evolutions/abilities-mcp-adapter.git
```

### Required companion plugin

You also need **[Abilities for AI](https://community.wickedevolutions.com/item/abilities-for-ai/)** — the plugin that registers WordPress abilities. Without it, the Adapter has nothing to expose.

## Built-in Tools

### Discovery & execution

| Tool | Description |
|------|-------------|
| `mcp-adapter-discover-abilities` | List all available abilities with category and tier (registration manifest at ability-name resolution) |
| `mcp-adapter-get-ability-info` | Get schema and metadata for a specific ability |
| `mcp-adapter-execute-ability` | Execute an ability with input parameters |
| `mcp-adapter-batch-execute` | Execute multiple abilities in a single request (max 20). Reach for compact-class abilities when the batch is broad — see [Notes — Paired ability classes](#paired-ability-classes) |
| `mcp-adapter/get-started` | Operator orientation entry point (`recommended_first_steps` available for ability plugins to populate) |

### Suite + status

| Tool | Description |
|------|-------------|
| `suite/get-status` | Return per-module category × tier permission state — the authorization gate at category resolution. Pair with `mcp-adapter-discover-abilities` for the registration manifest at ability resolution |

### Safety configuration (require `manage_options`)

| Tool | Description |
|------|-------------|
| `settings/get-redaction-list` | Read current redaction state |
| `settings/add-redaction-keyword` | Strengthen defaults — add a custom keyword (no friction) |
| `settings/remove-custom-keyword` | Reverse operator's own additions |
| `settings/restore-redaction-defaults` | Restore baseline list |
| `settings/remove-default-bucket3-keyword` | Weaken Bucket 3 default — in-chat 1/2 confirmation required |
| `settings/exempt-ability-from-bucket3` | Per-ability Bucket 3 unlock — in-chat 1/2 confirmation required |
| `settings/unexempt-ability-from-bucket3` | Re-lock an exemption |

## How Abilities Become MCP Tools

Abilities are exposed as MCP tools when either:

1. `show_in_rest` is set to `true` on the ability (WordPress 6.9+ standard)
2. `meta.mcp.public` is `true` (fallback for older registrations)

The adapter reads `input_schema` and `output_schema` to generate MCP-compatible definitions, and maps annotations like `readonly`, `destructive`, and `idempotent` to MCP hint fields. Per [PRINCIPLES.md](PRINCIPLES.md) Principle 3 (Adapter Is A Projection), the adapter projects the WordPress registry — it filters, redacts, annotates, scopes, and rate-limits, but it does not redefine schemas or invent alternate versions of business-domain abilities.

## Boundary event log (events the adapter emits)

The adapter emits structured boundary events through the `mcp_adapter_boundary_event` action hook for any third-party listener (the canonical consumer is [Abilities for AI](https://github.com/Wicked-Evolutions/abilities-for-ai)'s `BoundaryEventLogger`, which writes them to the `kl_boundary` table). Events emitted:

- `boundary.session.init` — MCP session created
- `boundary.session.terminated` — MCP session ended
- `boundary.auth.denied` — Bearer auth or scope check rejected a request
- `boundary.transport.error` — transport-layer failure
- `boundary.rate_limit_hit` — per-IP or per-user rate window exceeded

Events are sanitized at the boundary — third-party listeners never see raw secrets. Metadata-only allowlist applied as defense-in-depth on top.

## Usage with the Abilities MCP bridge

For remote access from any MCP-compatible AI client, install the [Abilities MCP](https://github.com/Wicked-Evolutions/abilities-mcp) bridge:

- **Claude Desktop:** download `abilities-mcp.mcpb` from the [bridge's latest GitHub Release](https://github.com/Wicked-Evolutions/abilities-mcp/releases/latest), drag into Claude Desktop, then upgrade to OAuth via `abilities-mcp upgrade-auth <site>` from terminal
- **Terminal MCP clients (Claude Code, Cursor, Codex, etc.):** `npm install -g @wickedevolutions/abilities-mcp`, then `abilities-mcp add-site <url>` — OAuth by default, with PKCE consent in your browser
- **Power-user `wp-sites.json` config:** see the [bridge README](https://github.com/Wicked-Evolutions/abilities-mcp#readme) for hand-curated multi-site configuration

## Creating Custom MCP Servers

```php
add_action( 'mcp_adapter_init', function( $adapter ) {
    $config = McpServerConfig::from_array([
        'server_id'              => 'my-server',
        'server_route_namespace' => 'my-plugin/v1',
        'server_route'           => 'mcp',
        'server_name'            => 'My MCP Server',
        'server_description'     => 'Custom MCP server',
        'server_version'         => '1.0.0',
        'mcp_transports'         => [ HttpTransport::class ],
        'tools'                  => [ 'my-plugin/my-tool' ],
    ]);
    $adapter->create_server_from_config( $config );
});
```

## Notes

### Four-layer permissions model

When an ability is denied, the rejection comes from one of four independent layers. The runtime error names the layer:

1. **Abilities for AI module permission** — per-blog read/write/delete toggle in *WP Admin → Abilities for AI → Permissions* (and on the adapter side, *WP Admin → Settings → MCP Abilities*). The runtime returns `[ability_disabled]` with the module name and where to fix it.
2. **WordPress capability** — the WordPress user the request authenticates as lacks the relevant capability. WordPress core REST returns `rest_forbidden` / `rest_cannot_*` codes.
3. **OAuth scope** — the bearer token does not include the scope the ability requires. The adapter's `OAuthScopeEnforcer::check()` returns an `insufficient_scope` rejection at dispatch time.
4. **Unclear** — generic 500, timeout, or malformed response. Check server logs.

The four gates apply together by design (see [PRINCIPLES.md](PRINCIPLES.md), Principle 5 — *Permissions Stay Layered*). The runtime error tells you which gate fired so you can act at the right layer.

### Paired ability classes

The product ships compact-vs-full pairs across the API by design. Each ability description names its payload tradeoff. Pick the pair member that matches the traversal you intend — compact for bulk discovery, full for targeted inspection. The pattern recurs across categories beyond `content/*`.

### Discovery vs authorization (two separate inspection surfaces)

`mcp-adapter-discover-abilities` returns the registration manifest — every ability that exists in the system, regardless of whether the current category × tier permissions allow it to execute. `suite/get-status` returns the authorization gate state at category × tier resolution. Both are valid surfaces; each answers a different question; neither substitutes for the other.

### Selected consent role on token refresh

The role-downgrade fix (#88, v1.4.5) persists the operator's selected role on the auth-code → access-token → refresh-token chain for tokens minted from the interactive consent screen. Auto-approve refresh / silent reauth does not currently carry the prior consent's role choice. Mitigation: explicit reauth (`abilities-mcp reauth <site> --scope=...` on the bridge CLI, or revoke + re-consent) renders a fresh consent screen and resets the chain to the chosen role. Tracked on [#94](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/issues/94).

## Naming Lineage

This plugin was originally a thin wrapper around `wordpress/mcp-adapter` (Composer package). It has been fully decoupled and is now a standalone codebase under the `WickedEvolutions\McpAdapter` namespace. The upstream package is credited but no longer a dependency. Per [PRINCIPLES.md](PRINCIPLES.md), we monitor `wordpress/mcp-adapter` as a reference implementation, but our adapter may differ where product requirements demand it, provided we preserve WordPress-native ability semantics.

## `wpab__` Resolver vs MCP Adapter

WordPress core (WP 7.0+) includes `WP_AI_Client_Ability_Function_Resolver` which converts abilities to AI tool calls with a `wpab__` prefix. This is designed for the `@wordpress/abilities` JS client. The MCP Adapter provides a different mapping — full MCP protocol compliance with annotations, session management, and multi-transport support. Both approaches coexist; the MCP Adapter is for external AI agent access, the `wpab__` resolver is for WordPress's built-in AI client.

## Evolving Knowledge

We continuously add knowledge docs, skills, and agent patterns to [knowledge.wickedevolutions.com](https://knowledge.wickedevolutions.com).

## Version

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Author

[Wicked Evolutions](https://wickedevolutions.com)

## License

GPL-2.0-or-later
