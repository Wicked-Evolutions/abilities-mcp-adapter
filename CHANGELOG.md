# Changelog

## [2.2.1] - 2026-03-05

### Added
- `patches/session-manager-get-lock.patch` — tracked patch file for MySQL GET_LOCK session locking
- `patches/README.md` — rationale, apply/reverse instructions, upstream status

### Fixed
- Cleaned inactive adapter copies from servers (hostinger-ai-assistant, wp-mcp-adapter)
- Cleaned orphaned `mcp_session_lock_*` transients from wp_options

### Changed
- Dead constants removed in patch: `LOCK_KEY_PREFIX`, `LOCK_MAX_ATTEMPTS` (unused after GET_LOCK migration)

---

## [2.2.0] - 2026-02-26

### Security (Opus review — session fixation, metadata leakage, race conditions)
- Session fixation prevention
- Metadata leakage fixes
- Race condition handling improvements

### Changed
- SessionManager upgraded with atomic locking (GET_LOCK) — deployed server-side

---

## [2.1.0] - 2026-02-24

### Security (Oracle review)
- Security hardening pass on session management and input validation

### Added
- Initial public release with bundled `wordpress/mcp-adapter` v0.4.0
- Automatic ability-to-tool discovery via `wp_get_abilities()`
- MCP tool validation enabled by default
- Three built-in discovery tools: discover-abilities, get-ability-info, execute-ability

---

## License

GPL-2.0-or-later
