# IrisProxyExtension — Transparent Network Proxy

## What This Does
System extension that intercepts ALL outbound TCP and UDP flows via
NEAppProxyProvider. HTTPS gets TLS MITM with full HTTP capture. HTTP gets
parsed directly. All other TCP/UDP gets passthrough relay with byte counting
and process attribution.

## Why This Design
NEAppProxyProvider gives per-flow access with process attribution
(sourceAppAuditToken). Unlike a packet tunnel, it operates at the flow level
so there's no need for a userspace TCP/IP stack. Accepting all traffic makes
the proxy the single source of truth for network activity — foundation for
consolidating DNS and firewall into one extension.

## Data Flow
```
Any outbound connection
  → macOS → NEAppProxyProvider.handleNewFlow()
  → FlowHandler routes by port:
    443 → TLS MITM → HTTP parse → ProxyCapturedFlow(.https)
     80 → HTTP parse → ProxyCapturedFlow(.http)
    UDP → datagram relay → ProxyCapturedFlow(.udp)
    other TCP → passthrough relay → ProxyCapturedFlow(.tcp)
  → XPC (ProxyXPCProtocol) → ProxyStore → UI
```

## Decisions Made
- **All traffic, not just HTTP(S)** — captures SSH, DNS, game traffic, etc.
  Non-HTTP flows get passthrough relay with byte counting + process info.
- **NEAppProxyProvider over NEPacketTunnelProvider** — per-flow metadata.
  Packet tunnel loses attribution. Apple TN3120 says don't use for monitoring.
- **SSLCreateContext for client TLS** — only Apple API with raw I/O callbacks
  for terminating TLS on NEAppProxyTCPFlow byte streams.
- **UDP via NEAppProxyUDPFlow** — per-datagram relay with NWConnection pool.
  Each unique destination gets its own connection.
- **ByteCounter + AtomicFlag** — thread-safe primitives for concurrent relay
  tasks without actor overhead.
- **Delta XPC protocol** — sequence-numbered flow updates minimize data transfer.

## Key Files
- `AppProxyProvider.swift` — flow entry point, accepts all TCP + UDP
- `FlowHandler.swift` — routes by port/protocol (+MITMRelay, +HTTPRelay, +Passthrough, +UDPRelay)
- `TLSInterceptor.swift` — CA loading, per-host cert generation
- `TLSSession.swift` — SSLCreateContext wrapper for client-facing TLS
- `RelayState.swift` — thread-safe shared state for relay task groups
- `ProxyXPCService.swift` — XPC listener + flow management
