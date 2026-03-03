# Changelog

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
