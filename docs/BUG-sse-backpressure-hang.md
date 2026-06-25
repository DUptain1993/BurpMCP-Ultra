# Diagnosis: MCP tool call hangs forever ("stuck spinner", no self-recovery)

Root-caused 2026-06-25 via a multi-agent investigation (5 readers → synthesis → adversarial
verification against the bundled MCP SDK 0.8.3 / Ktor 3.2.3 bytecode). High confidence; the
top hypothesis was **not** refutable, the competing "pure client-hook" theory **was** refuted.

## Symptom
A tool call (observed: `cors_probe`) shows in the **MCP Activity** table as *completed*
(e.g. 949 ms, Error: false, full result), but the MCP client (Claude Code) shows that same
call **pending forever** (57 min, no movement). The result was computed server-side but the
bytes never reached the client, and the session never recovers.

## Root cause — SSE response write hangs under client read-backpressure
1. **Dispatch is sequential and inline on the POST coroutine.** The SDK's
   `SseServerTransport.handlePostMessage` awaits `handleMessage → Protocol.onRequest`, which
   invokes the tool handler **inline**, then calls `transport.send(JSONRPCResponse)` — and only
   *after* that returns does the POST emit HTTP 202. (Empirically: a `tools/call` POST blocks
   until the response is delivered on the SSE stream.)
2. **The activity row is written before the send.** `ToolCallTracker` (ToolCallTracker.kt:37/42/45)
   invokes the handler, records the activity row (with the 949 ms / Error:false), then returns —
   all *before* the SDK's `transport.send`. So a logged row proves the handler returned, **not**
   that the response was delivered.
3. **The SSE write has no timeout and holds a per-session lock.** Ktor's
   `DefaultServerSSESession.send` takes a single per-session `Mutex`, then does
   `writeStringUtf8 + ByteWriteChannel.flush()` with **no `withTimeout`**. `flush()` is subject
   to TCP backpressure — it suspends until the socket send buffer drains.
4. **The client stopped reading.** Claude Code ran a **PostToolUse hook** ("total CNAME records:
   76" / "3 PostToolUse hooks ran") right before freezing — i.e. it stopped draining the SSE
   socket. The kernel TCP receive window closed, the server's send buffer filled, and `flush()`
   suspended **indefinitely**. The held `Mutex` then wedges every subsequent send/close for the
   session, and the POST never returns its 202. Permanent wedge, no self-recovery.

The `java.net.UnknownHostException: graphql.manyvets.com` in the log is a **red herring**: a
separate, earlier, *handled* request (Activity row 12, 73 ms) on the bounded `executeWithTimeout`
pool — off the SSE delivery coroutine entirely.

## Is it our bug?
**Partially.** The *trigger* is client-side (a slow/hung PostToolUse hook that stopped reading
the SSE socket). The no-timeout SSE write lives in the MCP SDK + Ktor, not our code. **But** our
extension uses the plain SSE transport with **no write-timeout, no send watchdog, and no
idle-session reaper**, so nothing on our side can detect or recover a wedged session.

## Version impact
**Not a regression.** The transport/dispatch model is byte-identical across the **released
2.1.0** (tag `8597226`) and the staged **2.1.1** (`586b958`); the 2.1.x work did **not** cause
or worsen this. Exposure has existed since the SSE transport was adopted. All versions affected.

## Secondary latent bugs found (real, but NOT the cause of this stall)
- **Unbounded direct sends** — `cors_probe` and 8 bridges call `api.http().sendRequest()` with
  **no timeout** (unlike `http_send_request`, which wraps `executeWithTimeout`). A black-holing
  host would hang the single dispatch coroutine. Sites: `WebProbeBridge.kt:29,63`,
  `ReconBridge.kt:31,112`, `GraphQlBridge.kt:70`, `InjectionBridge.kt:30`, `AnalysisBridge.kt:519`,
  `ScannerBridge.kt:726`, `ApiImportBridge.kt:181`, `ScanCheckBridge.kt:248`. Introduced with the
  recon/webprobe features (`7715f16`), predates 2.1.0.
- **Thread leak** — `executeWithTimeout` (HttpBridge.kt:1013-1031) submits to an unbounded
  `newCachedThreadPool`; on timeout it `future.cancel(true)`, but `Thread.interrupt` cannot abort
  Burp's native send or JDK DNS resolution, so stuck workers leak.

## Fix plan (prioritized)
1. **Bound the SSE send (primary).** Decorate the `Transport` passed to the SDK so `send()` runs
   under `withTimeout(...)`; on timeout, close the session and surface an error instead of wedging.
2. **Per-session watchdog / stuck-send reaper.** Track time-since-last-successful-flush; force-close
   a session whose send has been in-flight beyond a threshold (releases the `Mutex`, frees the POST).
3. **Bound every direct `api.http().sendRequest`** in the probe/scan bridges (route through a
   bounded helper with a sane default timeout).
4. **Cap the HTTP thread pool** (bounded max + queue + rejection) and document the interrupt limit.

## Immediate remedy if it recurs
- The spinner cannot self-recover (no write timeout). **Interrupt/restart the stuck client** (tears
  down the SSE GET → `flush()` fails → releases the lock), or **toggle the MCP server off/on** in the
  Burp extension tab.
- Add a **timeout to the offending PostToolUse hook** so it can't stall SSE reading.
- To *prove* it server-side while wedged: `jstack <burp-pid>` and grep for
  `DefaultServerSSESession|writeSSE|ByteWriteChannel|flush` (a coroutine/thread parked there) and
  for leaked `burpmcp-http-` workers.
