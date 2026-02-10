# Architecture Design Decisions

## TLS MITM Architecture (DECIDED - Hybrid approach)

### The Solution: Hybrid SSLCreateContext + NWConnection

```
Client App <-> [NEAppProxyTCPFlow raw bytes] <-> TLSSession (SSLCreateContext, server mode)
                                                    | decrypted HTTP |
                                              FlowHandler (HTTP parsing + capture)
                                                    | decrypted HTTP |
                                              NWConnection (TLS 1.3, client mode) <-> Real Server
```

**Client-facing (TLSSession.swift)**:
- SSLCreateContext with SSLSetIOFuncs for raw I/O callbacks
- Ring buffer + DispatchSemaphore bridges async flow.readData to sync SSL callbacks
- Presents generated per-host certificate (from TLSInterceptor)
- TLS 1.2 max (acceptable: client is on same machine)

**Server-facing (NWConnection)**:
- NWConnection with TLS parameters from TLSInterceptor.createClientTLSParameters()
- Full TLS 1.3 support to real servers
- Accepts all server certs (we're the MITM)

**Flow capture**:
- HTTPParser parses decrypted HTTP request/response in both directions
- CapturedFlow/CapturedRequest/CapturedResponse sent to ProxyXPCService
- IPDetailPopover "View Full Request/Response" works automatically when these are populated

### Future Upgrade Path
Replace SSLCreateContext with SwiftNIO EmbeddedChannel + NIOSSLHandler (BoringSSL).
NIOSSLHandler is channel-agnostic, proven on EmbeddedChannel.
Benefits: TLS 1.3, non-deprecated, better error handling.
Packages: swift-nio (2.94.0+), swift-nio-ssl (2.36.0+), swift-nio-transport-services (1.21.0+)

### Key Files
- `IrisProxyExtension/TLSSession.swift` - SSLCreateContext wrapper
- `IrisProxyExtension/TLSInterceptor.swift` - CA loading, per-host cert gen, ASN.1 DER
- `IrisProxyExtension/AppProxyProvider.swift` - FlowHandler with MITM relay
- `IrisProxyExtension/HTTPParser.swift` - HTTP/1.1 request/response parsing
- `IrisProxyExtension/ProxyXPCService.swift` - CapturedFlow models + XPC

---

## DNS Architecture

### IrisDNSExtension (NEDNSProxyProvider)
- Intercepts ALL system DNS queries as UDP AND TCP flows
- TCP DNS uses 2-byte big-endian length prefix per RFC 1035 Section 4.2.2
- Forwards via DoH to Cloudflare (1.1.1.1) using IP addresses directly (avoids DNS chicken-and-egg)
- Records queries with domain, type, response code, answers, TTL, latency, process name
- Communicates with app via XPC (DNSXPCProtocol)
- **CRITICAL**: After system extension install, NEDNSProxyManager must be configured
  - DNSProxyHelper.enableDNSProxy() is called automatically by ExtensionManager
  - Without this step, DNS traffic will NOT be routed to the extension

### IrisDNS Package (App Side)
- `DNSMessageParser`: RFC 1035 wire format parser with compression pointer handling
- `DoHClient`: RFC 8484 actor with URLSession, HTTP/2, statistics
- `DNSStore`: @MainActor store with XPC to extension, 2s refresh, search/filter
- `DNSMonitorView`: HSplitView with query list + detail/stats panel
- `DoHServerConfig`: Cloudflare, Cloudflare Family, Google, Quad9 with bootstrap IPs

### DNSProxyHelper (in IrisShared)
- Follows same pattern as NetworkFilterHelper
- Manages NEDNSProxyManager lifecycle (load/save/removeFromPreferences)
- providerBundleIdentifier: "com.wudan.iris.dns.extension"
- serverAddress: "1.1.1.1" (required by API even though we use DoH internally)

---

## Phase 3: NEPacketTunnelProvider — CANCELLED

Research conclusively determined NEPacketTunnelProvider is WRONG for Iris:
1. Requires full TCP/IP stack (lwIP) for stream reassembly from raw IP packets
2. Loses per-process metadata (`sourceAppAuditToken` not populated in system-wide mode)
3. Apple TN3120 explicitly says packet tunnels are for tunneling, NOT monitoring
4. Blocks user's VPN (only one packet tunnel can be active)
5. No HTTPS benefit - still sees ciphertext, TLS MITM still needs a proxy

Current architecture IS the optimal design:
```
NEFilterDataProvider  -> Connection visibility + per-process ID + firewall rules
NEAppProxyProvider   -> TLS MITM + HTTP parsing + flow capture
NEDNSProxyProvider   -> DNS-over-HTTPS + DNS query visibility
```
Upgrade path: NETransparentProxyProvider replaces NEAppProxyProvider if needed.

---

## Evidence-Based Scoring Model (Instance A)

Design principles for extending to all scanners:
- Weights 0.0 to 1.0 ONLY. No negative weights. Nothing reduces suspicion.
- Everything visible in audit list. Zero evidence = still shown.
- `isBaselineItem` is context label only, does NOT affect score.
- Score = sum of weights, clamped to [0, 1]. Severity: 0.8+ critical, 0.6-0.8 high, 0.3-0.6 medium, <0.3 low.
- IPSW baseline (baseline-25C56.json): 418 daemons, 460 agents, 674 kexts, 12 auth plugins
