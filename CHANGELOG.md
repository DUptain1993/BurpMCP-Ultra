# Changelog

All notable changes to BurpMCP-Ultra are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); this project uses
[Semantic Versioning](https://semver.org/) (see `docs/ROADMAP.md` for the semver convention).

## [2.2.1] — 2026-07-05

### Added
- `http_send_request` now returns an advisory **`warnings`** array when the method, URL, or a header
  value contains a raw CR/LF — the cause of Burp **"kettled"** HTTP/2 requests (issue #7). This lets
  an agent notice a stray newline (often emitted by the LLM) and self-correct. Advisory only — it
  never blocks, since sending CRLF on purpose (request-smuggling research) is a valid use.

## [2.2.0] — 2026-07-05 — Reliability, persistence & networking

Theme: reliability & persistence, plus the community-requested configurable bind host.

### Added
- **Configurable server bind host** (issue #4, contributed as PR #6 by **@Spark0618**, re-implemented
  hardened). The MCP + dashboard servers can bind to a chosen interface instead of loopback-only, for
  cross-machine / headless-Burp setups. Requested host resolves from `-Dburpmcp.bindHost`, else the
  `mcp_bind_host` preference, else `127.0.0.1`.
- **"Save & Rebind Now"** on the Server tab — hot-restarts the three servers on a new bind host
  **without an extension reload** (any live MCP client is briefly disconnected, as on a reload).
- **Durable dashboard activity** — MCP tool-call history now persists across extension reloads, Burp
  restarts, and crashes (project-tagged JSONL store), and repopulates both the native tab and the web
  dashboard on startup.

### Changed
- Bind-exposure / downgrade notices are logged to the **Output** tab with a `⚠ SECURITY` prefix
  (not the Errors tab) — they are warnings about a deliberate choice, not failures.
- Startup/log messages and all displayed connection URLs are now host-aware.

### Fixed
- **The 57-minute hang**: an SSE write to a client that stopped draining the stream could wedge the
  per-session write forever. Outbound SSE sends are now bounded by a timeout; on expiry the stalled
  session is torn down and the client reconnects (`TimeoutSseTransport` / `runWithSendTimeout`).
- **No-timeout hang class**: bounded the outbound HTTP sends in the probe/scan/import bridges.
- Restored MCP Activity rows are clickable again and counted in the live stats.
- A partial-init failure no longer orphans the listening sockets ("Address already in use" on the
  next reload): the unload handler is registered first and server start-up is wrapped so any failure
  stops the servers.

### Security
- A **non-loopback bind is gated**: it exposes Burp-driving tools and captured proxy history to the
  network behind only the bearer token, so it is honored **only** when the operator opts in
  (`mcp_allow_remote_bind` / `-Dburpmcp.allowRemoteBind`); otherwise the request is refused and
  downgraded to loopback. Exposure is warned loudly and written to the durable audit log. The
  Host-header + CORS allowlist extends to the configured host and this machine's own addresses only —
  never `anyHost()`. See `docs/SECURITY.md`.

## [2.1.1] — 2026-06-25

### Fixed
- MCP connection config corrected across every surface: the SSE endpoint is the **root path `/`**
  (not `/sse`) and a **bearer token is required**, single-sourced via `ConnectionInfo`.
- Systemic enum silent-failure bugs (B1–B7): closed-set parameters now fail loudly.
- `proxy_history_search` no longer silently returns zero for `search_in="url"`.

### Changed
- Version is single-sourced from the build (`BuildInfo.VERSION`) — no more hardcoded UI/dashboard drift.
- README accuracy pass (149 tools); LICENSE added.

## [2.1.0] — 2026-06-24

- Build compatibility (GitHub issues #2/#3): the fat JAR is pinned to JDK 17 bytecode so the MCP SSE
  ports bind reliably (a JAR built with Java 22+ silently failed to bind).
