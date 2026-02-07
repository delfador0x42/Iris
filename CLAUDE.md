# Instructions for Claude

## Who You Are Here
You are building Iris with Tal. Security software that protects people.
You are not cautious. You are thorough. Research everything, verify everything,
then build boldly. Push back when you disagree. Refactor freely.
Use private frameworks, reverse engineer binaries, never say impossible.
When stuck: try 3 alternative approaches before asking. Web search is free.

## Your Operating Rules
1. **≤100 lines per file. Max 300. One file, one job.** This is a HARD rule.
2. **Research before coding.** Web search every API you're unsure about.
   Your #1 failure mode is using APIs that don't exist.
3. **Read before writing.** Read existing files before modifying or creating.
   Your #2 failure mode is duplicating/contradicting existing code.
4. **Update CLAUDE.md every session.** Your future self remembers NOTHING.
   Current state, decisions, gotchas — if it's not written, it's lost.
5. **Build after every significant change.** Don't stack 5 file changes
   then discover the first one broke everything.
6. **Replicate existing patterns.** Look at how existing stores/views/XPC
   work. Copy that structure exactly for new features.

## When You're Stuck
1. Re-read the error message carefully
2. Web search the exact error or API
3. Try a different approach entirely
4. Read related Apple documentation or source code
5. Ask Tal — he wants to help





# Iris - AI Development Guide

## Quick Start

```bash
# Build
xcodebuild -project Iris.xcodeproj -scheme Iris -configuration Debug build

# Run tests
xcodebuild test -scheme Iris -destination 'platform=macOS'
```

The app requires System Extension approval in System Settings > Privacy & Security.

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                          IrisMainApp                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ ┌────────┐  │
│  │Process   │ │Security  │ │DiskUsage │ │ WiFi   │ │ DNS    │  │
│  │Store     │ │Store     │ │Store     │ │ Store  │ │ Store  │  │
│  └────┬─────┘ └────┬─────┘ └──────────┘ └────────┘ └───┬────┘  │
│       │XPC         │XPC                                 │XPC     │
└───────┼────────────┼────────────────────────────────────┼────────┘
        ▼            ▼                                    ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│IrisEndpoint  │ │IrisNetwork   │ │IrisProxy     │ │IrisDNS       │
│Extension     │ │Extension     │ │Extension     │ │Extension     │
│(ES)          │ │(NEFilter)    │ │(NEAppProxy)  │ │(NEDNSProxy)  │
└──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
```

## Package Responsibilities

| Package | Purpose | Key Files |
|---------|---------|-----------|
| IrisShared | Protocols, errors, ExtensionManager, ExtensionTypes | `ExtensionManager.swift`, `*XPCProtocol.swift`, `ExtensionTypes.swift` |
| IrisProcess | Process monitoring via ES | `ProcessStore.swift`, `ProcessInfo.swift` |
| IrisNetwork | Network monitoring + firewall rules | `SecurityStore.swift`, `SecurityRule.swift` |
| IrisDisk | Disk usage scanning | `DiskUsageStore.swift`, `DiskScanner.swift` |
| IrisSatellite | 3D satellite visualization | `SatelliteStore.swift`, `Renderer.swift` |
| IrisCertificates | CA/leaf cert generation, keychain | `CertificateGenerator.swift`, `CertificateStore.swift` |
| IrisWiFi | WiFi monitoring via CoreWLAN | `WiFiStore.swift`, `WiFiMonitorView.swift` |
| IrisProxy | Proxy data models (shared types) | `ProxyStore.swift`, `ProxyMonitorView.swift` |
| IrisDNS | DNS monitoring, DoH client, DNS models | `DNSStore.swift`, `DNSMonitorView.swift`, `DoHClient.swift` |
| IrisApp | Main UI, home screen, settings | `HomeView.swift`, `SettingsView.swift` |

## Key Entry Points

| Feature | Start Here |
|---------|------------|
| Extension installation | `ExtensionManager.swift` (manages .network, .endpoint, .dns) |
| Process list | `ProcessStore.swift` → `ProcessListView.swift` |
| Network connections | `SecurityStore.swift` → `NetworkMonitorView.swift` |
| HTTP inspection | `IPDetailPopover.swift` → `HTTPRawDetailView` |
| HTTP proxy flows | `ProxyStore.swift` → `ProxyMonitorView.swift` |
| Disk usage | `DiskUsageStore.swift` → `DiskUsageView.swift` |
| WiFi monitoring | `WiFiStore.swift` → `WiFiMonitorView.swift` |
| DNS monitoring | `DNSStore.swift` → `DNSMonitorView.swift` |
| TLS interception | `TLSInterceptor.swift` (in IrisProxyExtension) |
| Proxy flow handling | `AppProxyProvider.swift` → `FlowHandler` actor |
| Main navigation | `HomeView.swift` (circular stone menu, 8 sections) |

## System Extensions

| Extension | Bundle ID | Framework | XPC Service Name |
|-----------|-----------|-----------|-----------------|
| IrisNetworkExtension | `com.wudan.iris.network.extension` | NEFilterDataProvider | `99HGW2AR62.com.wudan.iris.network.xpc` |
| IrisEndpointExtension | `com.wudan.iris.endpoint.extension` | EndpointSecurity | `99HGW2AR62.com.wudan.iris.endpoint.xpc` |
| IrisProxyExtension | `com.wudan.iris.proxy.extension` | NEAppProxyProvider | `99HGW2AR62.com.wudan.iris.proxy.xpc` |
| IrisDNSExtension | `com.wudan.iris.dns.extension` | NEDNSProxyProvider | `99HGW2AR62.com.wudan.iris.dns.xpc` |

**Extension entry point pattern:**
```swift
import NetworkExtension
autoreleasepool { NEProvider.startSystemExtensionMode() }
dispatchMain()
```

**ExtensionManager** manages `.network`, `.endpoint`, and `.dns` extension types. Each has Published state + install/uninstall/polling.

## Patterns to Follow

### Store Pattern (MVVM)

All stores follow this structure:

```swift
@MainActor
public final class FooStore: ObservableObject {
    @Published public private(set) var items: [Item] = []
    @Published public private(set) var isLoading = false
    @Published public private(set) var errorMessage: String?
    private let logger = Logger(subsystem: "com.wudan.iris", category: "FooStore")
    private var xpcConnection: NSXPCConnection?
    public static let shared = FooStore()
    public func connect() { /* XPC setup */ }
    public func disconnect() { /* XPC teardown */ }
    public func refresh() async { /* XPC call */ }
}
```

### XPC Communication

- App → Extension: `NSXPCConnection` with Mach service name
- Service names: `99HGW2AR62.com.wudan.iris.{network,endpoint,proxy,dns}.xpc`
- Data format: JSON-encoded structs sent as `[Data]` arrays
- Protocols defined in: `Packages/IrisShared/Sources/IrisShared/Protocols/`
- Extension side: `NSXPCListener(machServiceName:)` + delegate

### Model Requirements

All models: `Identifiable, Sendable, Codable, Equatable`

## Entitlements

All entitlements files already include these NE provider types:
- `dns-proxy` - For NEDNSProxyProvider (IrisDNSExtension - code exists, not yet in Xcode project)
- `dns-settings` - For NEDNSSettingsManager
- `app-proxy-provider` - For NEAppProxyProvider (IrisProxyExtension - working)
- `content-filter-provider` - For NEFilterDataProvider (IrisNetworkExtension - working)
- `packet-tunnel-provider` - For NEPacketTunnelProvider (Phase 3 - not yet implemented)

## Known Issues / Gotchas

1. **Extension caching**: Old extensions can linger. Use `ExtensionManager.shared.cleanReinstallExtensions()` for Code 9 errors.
2. **App Groups must match**: `NEMachServiceName` in Info.plist must be prefixed with App Group from entitlements.
3. **Full Disk Access check**: Use `try? Data(contentsOf:)`, not `FileManager.isReadableFile()`.
4. **XPC service names**: Must match between Info.plist and code exactly.
5. **system_profiler SPAirPortDataType -json**: How to get MCS/NSS for WiFi (not CoreWLAN).
6. **SSLCreateContext is DEPRECATED**: TLS 1.2 max. Currently used for client-facing MITM (acceptable for local). Plan to migrate to SwiftNIO + swift-nio-ssl.
7. **NEAppProxyTCPFlow gives raw bytes**: Can't use NWConnection TLS for client-facing side. TLSSession.swift bridges this via SSLSetIOFuncs callbacks.
8. **No Package.swift files**: Packages are Xcode-managed local packages, not standalone SPM. Configure via Xcode project.
9. **IrisDNS not yet in Xcode project**: Files created but need to add to Xcode target dependencies.
10. **NEDNSProxyManager required**: After DNS extension activates, MUST configure NEDNSProxyManager or DNS traffic won't route to extension. DNSProxyHelper handles this.
11. **DNS XPC app group**: Main app entitlements MUST include `$(TeamIdentifierPrefix)com.wudan.iris.dns.xpc` for DNS XPC to work.
12. **DNS over TCP**: Uses 2-byte big-endian length prefix (RFC 1035 Section 4.2.2). Don't assume DNS is UDP-only.

## Don't Do This

- **Don't use `print()`** - Use `Logger` from os.log
- **Don't add singletons without injection** - Use `.shared` but allow init injection for testing
- **Don't put multiple views in one file** - Split into separate files
- **Don't hardcode magic numbers** - Named constants with comments
- **Don't use SSLCreateContext for new code** - It's deprecated, TLS 1.2 max

## Testing

- Framework: Swift Testing (`@Suite`, `@Test`, `#expect`)
- Mock pattern: `Tests/IrisSatelliteTests/Mocks/MockSatelliteDataSource.swift`
- Dependency injection: `SatelliteStore(dataSource:)` accepts mock data sources

## Team & Bundle IDs

- Team ID: `99HGW2AR62`
- App Bundle: `com.wudan.iris`
- Network Extension: `com.wudan.iris.network.extension`
- Endpoint Extension: `com.wudan.iris.endpoint.extension`
- Proxy Extension: `com.wudan.iris.proxy.extension`
- DNS Extension: `com.wudan.iris.dns.extension`

## File Locations

```
iris/
├── IrisApp/                    # App entry point (IrisMainApp.swift)
├── IrisNetworkExtension/       # Network filter extension (NEFilterDataProvider)
├── IrisEndpointExtension/      # Endpoint security extension (ESClient)
├── IrisProxyExtension/         # App proxy extension (NEAppProxyProvider)
│   ├── AppProxyProvider.swift  # Flow interception + FlowHandler actor
│   ├── TLSInterceptor.swift    # Per-host cert generation, CA from Keychain, ASN.1 DER encoding
│   ├── HTTPParser.swift        # HTTP/1.1 request/response parser + streaming + CONNECT detection
│   ├── ProxyXPCService.swift   # XPC + CapturedFlow/CapturedRequest/CapturedResponse
│   └── main.swift
├── IrisDNSExtension/           # DNS proxy extension (NEDNSProxyProvider) [NEW - not yet in Xcode]
│   ├── DNSProxyProvider.swift  # Intercepts DNS, forwards via DoH, records queries
│   ├── ExtensionDoHClient.swift # Lightweight DoH client using IP addresses directly
│   ├── DNSExtensionXPCService.swift # XPC service for app communication
│   └── main.swift
├── Packages/
│   ├── IrisShared/             # ExtensionManager, ExtensionTypes (.network/.endpoint/.dns), XPC protocols
│   ├── IrisProcess/            # Process monitoring
│   ├── IrisNetwork/            # Network monitor (SecurityStore, IPDetailPopover)
│   ├── IrisDisk/               # Disk usage
│   ├── IrisSatellite/          # 3D satellite (Metal)
│   ├── IrisCertificates/       # CA + leaf cert generation
│   ├── IrisWiFi/               # WiFi monitoring (CoreWLAN + system_profiler)
│   ├── IrisProxy/              # Proxy UI (ProxyStore, ProxyMonitorView, HTTPFlowDetailView)
│   ├── IrisDNS/                # DNS monitoring [NEW]
│   │   ├── Models/             # DNSMessage.swift, DNSQuery.swift
│   │   ├── Services/           # DoHClient.swift, DNSMessageParser.swift
│   │   ├── State/              # DNSStore.swift
│   │   └── Views/              # DNSMonitorView.swift, DNSQueryDetailView.swift
│   └── IrisApp/                # HomeView, SettingsView, Metal renderer
├── Tests/
└── Iris.xcodeproj/
```

## Deployment

- Target: macOS 26.2 (25C56) and above ONLY
- Private frameworks ARE accessible and can be used
- References: `references/program_examples/` has airport, mitmproxy, WARP binaries

## Current Development State (2026-02-07)

### Completed
- WiFi module (airport CLI replication with MCS/NSS, associate, prefs)
- IrisDNS package (models, parser, DoH client, store, views)
- IrisDNSExtension files (DNSProxyProvider with UDP+TCP, XPC, DoH client)
- ExtensionManager updated for .dns type + NEDNSProxyManager configuration
- DNSProxyHelper created (configures NEDNSProxyManager after extension install)
- HomeView updated with DNS Monitor (replaced Help)
- DNSXPCProtocol in IrisShared
- App entitlements updated with DNS XPC app group
- **TLS MITM**: TLSSession.swift created (SSLCreateContext wrapper for NEAppProxyTCPFlow)
- **handleHTTPSFlow rewritten**: Full TLS MITM using TLSSession (client-side) + NWConnection TLS (server-side)
- **CapturedFlow wired to XPC**: Both HTTP and HTTPS flows now call addFlow()/updateFlow()
- FlowHandler refactored with async/await, TaskGroup-based bidirectional relay

### Not Yet Done (Xcode Project Config Required)
- Add IrisDNSExtension as new target in Xcode
- Add IrisDNS package as dependency of IrisApp target
- Add SwiftNIO packages (future upgrade from SSLCreateContext)

### Phase 3: CANCELLED - NEPacketTunnelProvider
**Research conclusively determined NEPacketTunnelProvider is WRONG for Iris:**
1. Requires full TCP/IP stack (lwIP) for stream reassembly from raw IP packets - enormous complexity
2. Loses per-process metadata (`sourceAppAuditToken` not populated in system-wide mode)
3. Apple TN3120 explicitly says packet tunnels are for tunneling to remote servers, NOT monitoring
4. Blocks user's VPN (only one packet tunnel can be active)
5. No HTTPS benefit - still sees ciphertext, TLS MITM still needs a proxy

**Current architecture IS the optimal design:**
```
NEFilterDataProvider → Connection visibility + per-process ID + firewall rules
NEAppProxyProvider  → TLS MITM + HTTP parsing + flow capture
NEDNSProxyProvider  → DNS-over-HTTPS + DNS query visibility
```
If upgrade needed later: NETransparentProxyProvider replaces NEAppProxyProvider (same flow-level API, better integration)

## TLS MITM Architecture (DECIDED - Hybrid approach implemented)

### The Solution: Hybrid SSLCreateContext + NWConnection

```
Client App ←→ [NEAppProxyTCPFlow raw bytes] ←→ TLSSession (SSLCreateContext, server mode)
                                                    ↕ decrypted HTTP ↕
                                              FlowHandler (HTTP parsing + capture)
                                                    ↕ decrypted HTTP ↕
                                              NWConnection (TLS 1.3, client mode) ←→ Real Server
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
Research confirmed this works: NIOSSLHandler is channel-agnostic and proven on EmbeddedChannel.
Benefits: TLS 1.3, non-deprecated, better error handling.
Package URLs: swift-nio (2.94.0+), swift-nio-ssl (2.36.0+), swift-nio-transport-services (1.21.0+)

### Key Files
- `IrisProxyExtension/TLSSession.swift` - SSLCreateContext wrapper
- `IrisProxyExtension/TLSInterceptor.swift` - CA loading, per-host cert gen, ASN.1 DER
- `IrisProxyExtension/AppProxyProvider.swift` - FlowHandler with MITM relay
- `IrisProxyExtension/HTTPParser.swift` - HTTP/1.1 request/response parsing
- `IrisProxyExtension/ProxyXPCService.swift` - CapturedFlow models + XPC

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
