# Patches

Patches to the upstream `wordpress/mcp-adapter` vendor library that have been deployed to production but are not yet merged upstream.

## session-manager-get-lock.patch

**Replaces transient-based session locking with MySQL `GET_LOCK()` for atomic concurrency control.**

### Why

The upstream `SessionManager` uses a `get_transient()` → `set_transient()` pattern for per-user write locks. This is a classic TOCTOU (time-of-check-time-of-use) race condition: on shared hosting without a persistent object cache, two concurrent requests can both read `false` from `get_transient()` and both proceed to `set_transient()`, resulting in lost session updates.

In practice, Claude Code spawns 4 bridge instances simultaneously. All 4 send `initialize` concurrently. The transient-based lock fails to serialize these, causing session overwrites in `user_meta` and "Invalid or expired session" errors.

### What it changes

- **`acquire_lock()`**: Replaces the transient check-and-set loop with a single `SELECT GET_LOCK()` call. `GET_LOCK()` is atomic at the MySQL kernel level — no race condition is possible.
- **`release_lock()`**: Replaces `delete_transient()` with `SELECT RELEASE_LOCK()`.
- **Removes `LOCK_KEY_PREFIX` constant**: No longer used (GET_LOCK uses its own lock name format).
- **Removes `LOCK_MAX_ATTEMPTS` constant**: No longer used (GET_LOCK handles waiting internally via its timeout parameter).
- **Preserves `LOCK_TTL` constant**: Reused as the GET_LOCK timeout value.

### When to apply

Apply this patch if:
- Your WordPress site is on shared hosting (e.g., Hostinger, SiteGround, GoDaddy)
- You do NOT have a persistent object cache (Redis, Memcached)
- You experience concurrent session errors when multiple MCP clients connect simultaneously

If you have a persistent object cache, the upstream transient-based approach may work correctly since `wp_cache_add()` is atomic in Redis/Memcached. The patch is still safe to apply — GET_LOCK works everywhere MySQL is available.

### How to apply

From the plugin root directory:

```bash
cd vendor/wordpress/mcp-adapter
patch -p1 < ../../../patches/session-manager-get-lock.patch
```

To verify the patch applies cleanly without modifying files:

```bash
cd vendor/wordpress/mcp-adapter
patch -p1 --dry-run < ../../../patches/session-manager-get-lock.patch
```

To reverse the patch:

```bash
cd vendor/wordpress/mcp-adapter
patch -R -p1 < ../../../patches/session-manager-get-lock.patch
```

### Upstream status

Not yet submitted as an upstream PR to the WordPress AI Team's `wordpress/mcp-adapter` library. The plan is to evaluate whether to submit upstream after our product suite completes its dev sprint cycle.

### Deployed to

- wickedevolutions.com (2026-03-02)
- helenawillow.com (2026-03-02)

Both servers have backups of the original `SessionManager.php` alongside the patched version.
