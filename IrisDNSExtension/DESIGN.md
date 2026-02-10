# IrisDNSExtension — DNS-over-HTTPS Proxy

## What This Does
System extension that intercepts all DNS queries via NEDNSProxyProvider and
forwards them over HTTPS (DoH) to a configurable resolver (Cloudflare,
Google, Quad9, etc.). Logs every query with type, response, and latency.

## Why This Design
NEDNSProxyProvider is the only Apple API for intercepting DNS at the system
level without a VPN. It receives raw DNS wire-format packets (both UDP and
TCP) and lets us re-route them. DoH encrypts queries that would otherwise
be plaintext UDP on the wire.

## Data Flow
```
Any app → DNS lookup (A/AAAA/CNAME/...)
  → macOS DNS subsystem → NEDNSProxyProvider.handleNewFlow()
  → Read raw DNS query bytes (UDP or TCP with 2-byte length prefix)
  → DNSParser: decode wire format → domain, type, ID
  → DoHClient: POST query bytes to https://resolver/dns-query
  → DoHClient: receive answer bytes
  → Write answer back to flow
  → DNSQueryRecord → XPC (DNSXPCProtocol) → DNSStore → UI
```

## Decisions Made
- **NEDNSProxyProvider over packet tunnel** — DNS proxy is purpose-built for
  DNS interception. Doesn't block the user's VPN slot. Coexists with content
  filter and app proxy.
- **DoH over DoT** — HTTPS blends with normal web traffic (harder to block).
  Uses standard URLSession. DoT (port 853) is easily fingerprinted.
- **TCP + UDP handling** — DNS over TCP uses a 2-byte length prefix per
  RFC 1035 4.2.2. The extension handles both transport types.
- **NEDNSProxyManager auto-configuration** — DNSProxyHelper configures
  NEDNSProxyManager after the extension activates. This was a critical
  missing piece — the extension won't receive flows without it.
- **Wire format preserved** — queries forwarded as raw bytes to DoH server
  (RFC 8484 POST with application/dns-message). No re-encoding needed.

## Key Files
- `DNSProxyProvider.swift` — NEDNSProxyProvider subclass, flow entry point
- `DNSProxyProvider+FlowHandlers.swift` — UDP/TCP flow read/write
- `DNSProxyProvider+Parsing.swift` — DNS wire format parsing helpers
- `ExtensionDoHClient.swift` — Lightweight DoH client (IP-based, no DNS needed)
- `DNSExtensionXPCService.swift` — Mach XPC listener, DNSXPCProtocol
- DNSProxyHelper lives in `Packages/IrisShared/` (configures NEDNSProxyManager)
