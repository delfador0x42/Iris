# IrisNetworkExtension — Content Filter

## What This Does
System extension that intercepts all network flows via NEFilterDataProvider.
Logs every connection (process, remote host, port, direction, bytes) and
enforces user-defined firewall rules (allow/deny by process, domain, or port).

## Why This Design
NEFilterDataProvider is the only Apple API that sees every TCP/UDP flow with
full process attribution (sourceAppAuditToken) without requiring a VPN or
packet tunnel. It runs as a system extension with kernel-level hooks, so it
sees traffic even from other sandboxed apps.

## Data Flow
```
Any app → TCP/UDP connect
  → macOS kernel → NEFilterDataProvider.handleNewFlow()
  → FilterDataProvider: log connection + check rules
  → .allow / .drop verdict
  → XPC (NetworkXPCProtocol) → SecurityStore in main app → UI
```

## Decisions Made
- **NEFilterDataProvider over NETransparentProxy** — filter sees ALL flows
  including UDP; transparent proxy only gets TCP. Filter also doesn't require
  the app to handle actual data relay.
- **Rules evaluated in-extension** — latency matters for verdict decisions.
  Rules are pushed to the extension, not fetched per-flow.
- **JSON over XPC** — connections serialized as `[Data]` array. Simple,
  debuggable, fast enough for monitoring rates.

## Key Files
- `FilterDataProvider.swift` — NEFilterDataProvider subclass, flow entry point
- `FilterDataProvider+FlowHandling.swift` — Verdict logic per flow
- `FilterDataProvider+RuleEngine.swift` — Rule matching against flows
- `FilterDataProvider+ConnectionTracking.swift` — Active connection state
- `XPCService.swift` — Mach XPC listener, NetworkXPCProtocol conformance
- `NetworkFilterManager.swift` — NEFilterManager config (enable/disable/status)
