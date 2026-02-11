# IrisProxyExtension — HTTPS MITM Proxy

## What This Does
System extension that intercepts TCP flows via NEAppProxyProvider, performs
TLS man-in-the-middle on HTTPS connections, and captures full HTTP
request/response pairs for inspection in the UI.

## Why This Design
NEAppProxyProvider gives per-flow TCP access with process attribution
(sourceAppAuditToken). Unlike a packet tunnel, it operates at the flow level
so there's no need for a userspace TCP/IP stack. Combined with a dynamically
generated CA certificate, it enables full HTTPS inspection.

## Data Flow
```
App makes HTTPS request
  → macOS → NEAppProxyProvider.handleNewFlow()
  → FlowHandler: read CONNECT or SNI to get hostname
  → TLSSession: terminate client TLS (SSLCreateContext + generated cert)
  → NWConnection: connect to real server with TLS
  → Relay loop: client ↔ decrypt ↔ parse HTTP ↔ encrypt ↔ server
  → ProxyCapturedFlow → XPC (ProxyXPCProtocol) → ProxyStore → UI
```

## Decisions Made
- **NEAppProxyProvider over NEPacketTunnelProvider** — proxy gives per-flow
  metadata (process name, audit token). Packet tunnel loses all attribution
  in system-wide mode and requires lwIP. Apple TN3120 explicitly says packet
  tunnels aren't for monitoring.
- **SSLCreateContext for client TLS** — only Apple API that accepts raw I/O
  callbacks (SSLSetIOFuncs) for terminating TLS on a raw byte stream from
  NEAppProxyTCPFlow. Security framework, no third-party deps.
- **NWConnection for server TLS** — handles TLS 1.3, ALPN, certificate
  validation automatically. Clean async API.
- **Hybrid approach** — SSLCreateContext (client-facing) + NWConnection
  (server-facing). Future: SwiftNIO EmbeddedChannel + NIOSSLHandler.
- **HTTP parsing in-extension** — parsed on decrypted stream, only
  headers + body preview cross XPC.
- **RelayState class** — NSLock-based shared state for @Sendable TaskGroup
  closures (Swift concurrency requires it for mutable state in task groups).

## Key Files
- `AppProxyProvider.swift` — NEAppProxyProvider subclass, flow entry point
- `FlowHandler.swift` — Routes flows to MITM/HTTP/passthrough (+MITMRelay, +HTTPRelay, +Passthrough)
- `TLSInterceptor.swift` — CA loading, per-host cert generation (+ASN1, +CertBuilder, +DERParsing)
- `TLSSession.swift` — SSLCreateContext wrapper (+Handshake, +IOCallbacks, +ReadWrite)
- `RelayState.swift` — Thread-safe shared state for relay task groups
- `ProxyXPCService.swift` — Mach XPC listener (+FlowManagement, +XPCProtocol)
- HTTPParser in `Shared/` (compiled into all targets)
