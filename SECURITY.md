# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Abilities MCP Adapter, **do not open a public issue.**

Instead, please use [GitHub's private vulnerability reporting](https://github.com/Wicked-Evolutions/abilities-mcp-adapter/security/advisories/new) to report it directly.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

We review private vulnerability reports as bandwidth allows. We do not commit to specific response or fix timelines — this is a small team, and timing depends on severity, complexity, and what else is in flight. We will respond when we have something useful to say. Critical issues are prioritized.

## Scope

This policy covers:

### MCP protocol surface
- JSON-RPC handling, session management, transport (HTTP, GET/SSE)
- Schema transformation and input validation
- Origin allowlist + CORS handling

### Safety controls
- Three-bucket response redaction at the `/mcp` boundary (Bucket 1 secrets always-on, Bucket 2 + Bucket 3 configurable)
- Per-ability exemption mechanism
- Boundary event sanitization (raw `api_key` is hashed before reaching listeners; auth-denied tags carry truncated IPs and enum reason codes)
- One-time confirmation tokens for AI-initiated weakening of safety defaults (60s TTL, single-use, bound to session+ability+params)

### Operator-facing
- Admin settings page security (Settings → MCP Abilities, Settings → MCP Safety)
- AI-callable settings abilities (all gated by `manage_options`)
- Rate limiter at `/mcp` boundary, including trusted-proxy IP detection rules

For vulnerabilities in the MCP bridge or ability plugins, use the same private reporting feature on the relevant repository:
- [abilities-mcp](https://github.com/Wicked-Evolutions/abilities-mcp/security/advisories/new) — Node bridge
- [abilities-for-ai](https://github.com/Wicked-Evolutions/abilities-for-ai/security/advisories/new) — ability provider

## Out of scope

- WordPress core security — report to WordPress Security Team
- Third-party plugins that register abilities — report to those plugin authors
- Theme-level vulnerabilities

## Supported Versions

We support the latest released version. Older versions do not receive security patches — please update.
