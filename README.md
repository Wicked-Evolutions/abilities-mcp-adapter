# Abilities MCP Adapter

Converts WordPress abilities into MCP (Model Context Protocol) tools, resources, and prompts. Any ability registered via `wp_register_ability()` automatically becomes accessible to AI agents — zero configuration required.

## Features

### Discovery & execution

- **Automatic discovery** — abilities with `show_in_rest` or `mcp.public` metadata become MCP tools, regardless of which plugin registered them
- **Built-in MCP tools** — discover abilities, get info, execute single, execute batch
- **Permission metadata** — abilities carry `permission` (read/write/delete) and `enabled` state in MCP annotations
- **MCP annotations** — readonly, destructive, idempotent hints flow through to tool definitions
- **Schema transformation** — JSON Schema to MCP-compatible format with automatic wrapping
- **Error mapping** — WP_Error objects map cleanly to MCP error codes
- **HTTP transport** — REST API endpoint with session management, plus minimal Server-Sent Events stub

### Safety surface (v1.4.x)

- **Three-bucket response redaction** — secrets always filtered (passwords, API keys, tokens, hashes); payment / regulated identifiers and contact PII filtered by default with operator-controlled overrides; type-aware markers preserve schema shape
- **Per-ability exemptions** — operators unlock contact PII visibility on specific abilities (e.g. CRM workflows that legitimately need email) without weakening defaults globally
- **Origin allowlist + scoped CORS** — defense-in-depth against DNS rebinding; CORS scoped to MCP routes only, no global REST API side effects
- **Rate limiting at /mcp boundary** — per-IP and per-user windows, with Cloudflare and custom-allowlist trusted-proxy presets
- **Boundary event log** — structured events for session lifecycle, auth denials, transport errors, rate-limit hits, and settings audit changes (consumed by [Abilities for AI](https://github.com/Wicked-Evolutions/abilities-for-ai)'s `kl_boundary` writer when present)
- **Sanitized event hooks** — third-party listeners receive sanitized metadata only; raw API keys are hashed before any listener fires

### Operator UI

- **Settings → MCP Abilities** — per-ability enable/disable controls, permission tier overrides
- **Settings → MCP Safety** — master redaction toggle (with warning checkbox), keyword editor per bucket, per-ability exemption list, trusted-proxy configuration
- **AI-callable safety configuration** — operators can ask their AI to read or strengthen safety settings; weakening default safety requires in-chat 1/2 confirmation; Bucket 2 (payment/regulated) cannot be weakened through chat at any granularity

## Requirements

- WordPress 6.9+ (Abilities API)
- PHP 8.0+

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
| `mcp-adapter-discover-abilities` | List all available abilities with category and tier |
| `mcp-adapter-get-ability-info` | Get schema and metadata for a specific ability |
| `mcp-adapter-execute-ability` | Execute an ability with input parameters |
| `mcp-adapter-batch-execute` | Execute multiple abilities in a single request (max 20) |

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

## Permission Metadata

Each ability carries permission metadata in its MCP annotations:

- **`permission`** — `read`, `write`, or `delete`, derived from ability annotations
- **`enabled`** — boolean, controlled via Settings → MCP Abilities

When a disabled ability is called, the adapter returns a structured error:

```json
{
  "error": "permission_required",
  "permission": "write",
  "ability": "content/create",
  "enabled": false
}
```

## How Abilities Become MCP Tools

Abilities are exposed as MCP tools when either:
1. `show_in_rest` is set to `true` on the ability (WordPress 6.9+ standard)
2. `meta.mcp.public` is `true` (fallback for older registrations)

The adapter reads `input_schema` and `output_schema` to generate MCP-compatible definitions, and maps annotations like `readonly`, `destructive`, and `idempotent` to MCP hint fields.

## Usage with MCP Bridge

For remote access from any MCP-compatible AI client or IDE, use the [Abilities MCP](https://github.com/Wicked-Evolutions/abilities-mcp) bridge:

```json
{
  "mcpServers": {
    "wordpress": {
      "command": "node",
      "args": ["/path/to/abilities-mcp/abilities-mcp.js"]
    }
  }
}
```

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

## Naming Lineage

This plugin was originally a thin wrapper around `wordpress/mcp-adapter` (Composer package). It has been fully decoupled and is now a standalone codebase under the `WickedEvolutions\McpAdapter` namespace. The upstream package is credited but no longer a dependency.

## `wpab__` Resolver vs MCP Adapter

WordPress core (WP 7.0+) includes `WP_AI_Client_Ability_Function_Resolver` which converts abilities to AI tool calls with a `wpab__` prefix. This is designed for the `@wordpress/abilities` JS client. The MCP Adapter provides a different mapping — full MCP protocol compliance with annotations, session management, and multi-transport support. Both approaches coexist; the MCP Adapter is for external AI agent access, the `wpab__` resolver is for WordPress's built-in AI client.

## Evolving Knowledge

We continuously add knowledge docs, skills, and agent patterns to [knowledge.wickedevolutions.com](https://knowledge.wickedevolutions.com).

## Version

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Disclaimer

Humans make mistakes — as we know from the present day and history. Humans trained AI. AI acts accordingly. AI predicts probability based on the context window it holds. It is trained to sound certain, as if everything is truth, and to "fix" everything so the human becomes satisfied.

Learn how to communicate with AI. You are fully responsible for using AI in your life, business, and projects. Using these products is your personal responsibility to learn and own.

## Author

[Wicked Evolutions](https://wickedevolutions.com)

## License

GPL-2.0-or-later
