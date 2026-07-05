# Security model

BurpMCP-Ultra exposes an MCP server that can **drive your Burp Suite** — send arbitrary HTTP
requests, run scans, read your captured proxy history (which contains real requests, cookies, and
tokens), manage Collaborator, and more. Treat access to it as equivalent to control of your Burp.

For the full capability audit see `docs/security-and-capability-review.md`. This document covers the
trust boundary and the operator controls.

## Default: loopback only

Out of the box the three servers (MCP SSE `9876`/`9877`, dashboard `9878`) bind to `127.0.0.1`
only. Binding to loopback is not by itself a trust boundary (a malicious web page can target
localhost, and DNS rebinding can make responses cross-origin readable), so three independent
transport controls are always installed together (`SecurityConfig`):

1. **Host-header allowlist** — defeats DNS rebinding; a rebound request carries a `Host` not on the
   allowlist and is rejected before any handler runs.
2. **Origin lockdown** — cross-origin browser requests are rejected; CORS only ever advertises the
   configured host origins, never `anyHost()`.
3. **Per-session bearer token** — required on every request (Authorization header, `mcp_token`
   cookie, or `?token=`). Surfaced only in the local Burp UI (Server tab), never in logs.

## Operator-only gates

These are set via Burp preferences / persistence. **An MCP agent cannot change them** — only the
human operator can.

| Preference | Default | Effect |
|---|---|---|
| `mcp_scope_mode` | `warn` | Gates outbound HTTP against Burp's target scope (`off`/`warn`/`enforce`). |
| `mcp_allow_destructive` | `false` | Blocks `burp_shutdown`, project/user config import until enabled. |
| `mcp_allow_remote_bind` | `false` | **Must be `true` for any non-loopback bind to be honored** (see below). |

A durable audit trail of security-relevant tool calls is written to `~/.burpmcp-ultra-audit.jsonl`.

## Configurable bind host (issue #4 / PR #6)

You can bind the servers to a specific interface (e.g. a LAN IP, or `0.0.0.0` for all interfaces)
for cross-machine or headless-Burp setups. **This exposes Burp control to the network**, so it is
gated.

### How the gate works (`BindHostPolicy`)

The requested host resolves from `-Dburpmcp.bindHost` → the `mcp_bind_host` preference → `127.0.0.1`.
It is then classified and gated:

- **loopback** (`127.0.0.1`, `localhost`, `::1`) → always allowed.
- **non-loopback** (a concrete IP or `0.0.0.0`) → allowed **only if** the operator has opted in via
  `mcp_allow_remote_bind=true` (or `-Dburpmcp.allowRemoteBind=true`). Without the opt-in the request
  is **refused and downgraded to `127.0.0.1`**, with a warning.
- **invalid / blank** → downgraded to `127.0.0.1`.

When a non-loopback bind is honored:
- a `⚠ SECURITY` warning is logged (Output tab) and shown in the Server tab,
- a durable `server.remote_bind` entry is written to the audit log,
- the Host-header + CORS allowlist is extended to the configured host **and this machine's own
  interface addresses only** — so a real remote client's `Host` passes the anti-rebinding check,
  but the allowlist is still never `anyHost()`.

### Setting it

- **UI**: Server tab → *Server Bind Address* → enter the host, tick *Allow remote bind* (a
  non-loopback value triggers a confirmation of the network exposure), then **Save & Rebind Now**
  (applies live, no reload) or reload the extension.
- **JVM flags** (headless): `-Dburpmcp.bindHost=0.0.0.0 -Dburpmcp.allowRemoteBind=true`.

### What still protects you when exposed — and what does not

- **Still enforced**: the bearer token on every request, the Host/Origin allowlist, all operator
  gates. A caller without the token cannot invoke anything.
- **What you take on**: the bearer token becomes the *only* barrier between the network and full
  Burp control. There is no rate-limiting or lockout on token attempts. If the token leaks (it is
  shown in the Server tab and embedded in your MCP client config), anyone on the reachable network
  can drive your Burp.

### Recommendation

Prefer keeping loopback the default and fronting remote access with an **SSH tunnel or a reverse
proxy** you control (bound to the NIC, rewriting `Host` to a loopback allowlist entry) so the
network-side access control is explicit. Use the built-in remote bind only on trusted networks, and
revert to `127.0.0.1` when you are done.

## Reporting a vulnerability

Please report security issues privately to the maintainer (see the repo README / profile:
GitHub `Cy-S3c`, Telegram `@D4RK_V0RT3X`) rather than opening a public issue.
