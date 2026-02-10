# Instructions for Claude

## Core Principle
Understanding first. Code is the artifact of understanding, not the goal.
Before you write a line of code, understand the problem at the deepest level
you can reach. When you understand deeply enough, the code writes itself.
When you don't understand deeply enough, no amount of coding skill saves you.

## How to Go Deep
1. Read the RFC/spec, not a blog post ABOUT the spec
2. Read source code and headers, not just API documentation
3. Disassemble binaries when source isn't available
4. Write throwaway experiments to test your understanding
5. Map the complete data flow end-to-end before designing
6. Ask: "what would I build if this API didn't exist?"
   That answer IS your understanding of the problem.
7. Ask: "what's actually happening at the byte/syscall level?"
   If you can't answer, you don't understand yet. Research more.

## Research Depth Levels
- Level 1: "Does this API exist?" ← bare minimum, where you usually stop
- Level 2: "How does this API work internally? Failure modes? Edge cases?"
- Level 3: "What would I build if this API didn't exist?"
- Level 4: "What does the RFC say? What does the kernel do? What bytes move where?"
For core functionality: always reach Level 3-4.
For glue code: Level 1-2 is fine.

## Engineering Standards
- Build from first principles when the problem warrants it.
  Don't reach for a library until you understand what the library does.
- Minimal dependencies. Understand everything you import.
- Simple code > clever code. If it needs a comment to explain, simplify it.
- Measure performance, don't guess. Prototype before committing.
- Think like an attacker: every input untrusted, every boundary a surface.
- ≤100 lines per file. One file, one job. Max 300.

## Your Workflow
1. Understand: research the problem to depth Level 3-4
2. Map: draw the data flow end-to-end (in your head or in notes)
3. Design: identify the minimal set of components, one job each
4. Prototype: write throwaway code to test your riskiest assumption
5. Build: small files, clear names, build after every significant change
6. Verify: test it, measure it, attack it
7. Record: update notes for your future self (who remembers nothing)

## When You're Stuck
1. You probably don't understand deeply enough. Research more.
2. Re-read the error — really read it, don't skim
3. Web search the exact error or API signature
4. Try a completely different approach (not a variation — DIFFERENT)
5. Read the actual source code of the thing that's failing
6. Ask the user — they want to help

## Relationship
- Close collaborator. Be honest, disagree freely, push back.
- Never say impossible. Say "here's what it would take."
- The user wants ambitious implementations and honest feedback.

## Documentation
Every module and extension gets a DESIGN.md at its root.
These are for the human — explain WHY, not HOW. The code shows HOW.

Structure (keep under 50 lines):
1. What This Does — one paragraph, plain English
2. Why This Design — the decisions, not the implementation
3. Data Flow — end-to-end, from input to output
4. Decisions Made — what was chosen, what was rejected, why
5. Key Files — one line each

Update DESIGN.md when architecture changes.
Write it as you build, not after — decisions are freshest in the moment.




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

## APT Attack Surface & Defenses

Full red team report, scanner inventory, and gap analysis are in `../iris-research/`:
- **[THREAT_MODEL.md](../iris-research/THREAT_MODEL.md)** — 10 nation-state attack scenarios with MITRE ATT&CK mapping
- **[SCANNER_INVENTORY.md](../iris-research/SCANNER_INVENTORY.md)** — All 20+ scanners cataloged with capabilities and gaps
- **[DETECTION_GAPS.md](../iris-research/DETECTION_GAPS.md)** — P0-P3 gap analysis with effort/impact matrix

### Critical Finding: IrisSecurity Package Not In Xcode Project

SecurityAssessor.assess() only calls SystemSecurityChecks.runAll() (8 checks).
BUT: 14 of 18 scanners ARE wired to Views (ThreatScanView runs 11, plus PersistenceView/EventTapView/DylibHijackView/FileIntegrityView/SupplyChainView).
The REAL blocker: IrisSecurity package has ZERO entries in pbxproj. HomeView line 114 renders PlaceholderView instead of SecurityHubView. Package compiles in isolation but is invisible to the app binary.

**Truly orphaned scanners (4, not 16):** RansomwareDetector, EntropyAnalyzer, AVMonitor, PersistenceMonitor
**Wired to views but unreachable:** All 14 others (package not in Xcode project)

### Top 10 Attack/Parry Pairs

**1. ATTACK: Operation PHANTOM THREAD — DNS Tunneling (T1071.004)**
Base32-encoded data in subdomain labels, 1.2 MB/hour exfil
**PARRY**: DNSStore has all query data → needs DNSThreatAnalyzer (entropy on labels, frequency per base domain)
**STATUS**: Data collected, analyzer not yet built

**2. ATTACK: Operation GOLDEN BRIDGE — Supply Chain + Shell Injection (T1195, T1059.004)**
Trojanized package modifies .zshrc, adds `curl|bash` to build pipeline
**PARRY**: SupplyChainAuditor (taps/npm/pip) + PersistenceScanner+Shell → needs ShellConfigAnalyzer (content parsing)
**STATUS**: Scanners exist but don't analyze shell config content

**3. ATTACK: Operation DEEP CURRENT — Encrypted C2 on Non-Standard Port (T1573.002, T1571)**
TLS 1.3 on port 8443, beacons every 30s ± jitter
**PARRY**: NetworkAnomalyDetector has beaconing CV analysis + C2 port list → just needs WIRING
**STATUS**: Detector exists, orphaned from SecurityAssessor

**4. ATTACK: Operation SILK ROAD — LOLBin Chain (T1059.002, T1218)**
osascript → curl → python3 → sqlite3 TCC.db, no malware on disk
**PARRY**: LOLBinDetector (40+ LOLBins, parent→child, keychain dumps) → needs WIRING
**STATUS**: Detector exists with MITRE IDs, orphaned

**5. ATTACK: Operation CRYSTAL PALACE — Auth Plugin Persistence (T1547.002)**
Authorization plugin in SecurityAgentPlugins + auth.db mechanism insertion
**PARRY**: PersistenceScanner finds plugins on disk → needs auth.db parsing
**STATUS**: Partial — scans directory but doesn't verify auth.db wiring

**6. ATTACK: Operation SHADOW PUPPET — FinderSync Keylogger (T1056.001, T1547.015)**
FinderSync extension auto-loads with Finder, runs CGEventTap keylogger
**PARRY**: EventTapScanner detects CGEventTap → needs FinderSync/Spotlight/QuickLook enumeration
**STATUS**: Event tap detection works, extension enumeration missing

**7. ATTACK: Operation QUICKSILVER — Chunked HTTP Exfiltration (T1041, T1030)**
4KB POST bodies to compromised WordPress, looks like normal API traffic
**PARRY**: NetworkConnection has bytesUp/bytesDown → needs exfil ratio analysis
**STATUS**: Data available, analysis not built

**8. ATTACK: Operation ROOTKIT HOTEL — Kext/SysExt Persistence (T1547.006)**
Malicious kext hooks VFS to hide files and intercept network
**PARRY**: PersistenceScanner + FileSystemBaseline monitor Extensions dirs → needs kextstat comparison
**STATUS**: File detection works, runtime detection limited by architecture

**9. ATTACK: Operation WHISPER NET — ICMP Covert Channel (T1095)**
Encoded payloads in ICMP echo request data field
**PARRY**: Architectural gap — NEFilter only sees TCP/UDP, no ICMP visibility
**STATUS**: No clean solution in current extension framework

**10. ATTACK: Operation GLASS HOUSE — TCC Bypass (T1005, T1552.001)**
Direct TCC.db modification grants FDA/ScreenRecording/Accessibility
**PARRY**: TCCMonitor SHA256 baselines TCC.db + flags high-risk grants → needs WIRING
**STATUS**: Detector exists, orphaned

### IrisSecurity Package — Scanner Summary (51 files, 8095 lines)

| Scanner | MITRE | Effectiveness | Critical Bugs |
|---------|-------|--------------|---------------|
| SystemSecurityChecks (8) | T1562, T1486, T1553, T1021, T1078 | ACTIVE, works | None |
| DyldEnvDetector | T1574 | 85% — best scanner | Minor: shell eval/sourcing evasion |
| DylibHijackScanner + MachOParser | T1574.001, T1574.004 | 50% | Fat binary: only parses first arch; no runtime verification |
| AuthorizationDBMonitor | T1547.002 | 50% | Only monitors 10 of 1000+ rights; mtime check bypassable |
| FileSystemBaseline (FIM) | T1565, T1036 | 40-50% | 50MB file limit; no code signing check; baseline persistence fragile |
| LOLBinDetector (33 LOLBins) | T1059, T1218, T1555, T1005 | 35-40% | Only 33 entries (not 40+); parent-child only 1 level deep; renamed bins bypass |
| EventTapScanner | T1056.001 | 30% | flagsMask vs eventsOfInterest bug; benign list only 5 entries (massive FPs) |
| ProcessIntegrityChecker | T1055, T1574.006 | 25-30% | proc_regionfilename scans 10K of 50-200K regions; same-name hijack miss |
| CredentialAccessDetector | T1552, T1555 | 20% | Browser cookie touch = FP; bash-wrapped commands invisible |
| StealthScanner (9 techniques) | T1564, T1546, T1556, T1548 | 20% | Emond check dead (removed macOS 10.11+); SUID scan only 5 dirs |
| NetworkAnomalyDetector | T1571, T1573, T1071 | 15% | **BROKEN**: netstat has no PIDs on macOS; beaconing dead code (never called); CV<0.3 = 80% FP |
| TCCMonitor | T1557, T1005 | 5% | **BROKEN**: SIP blocks TCC.db reads on ALL modern macOS; sqlite3 schema outdated |
| SupplyChainAuditor | T1195 | 40% | Typosquatting: no legit-package reference set; Xcode plugin check obsolete (Xcode 9+) |
| XPCServiceAuditor | T1559 | 40% | Mach service: no known-good whitelist; socket perms unchecked |
| KextAnomalyDetector | T1547.006 | 40% | Half the rootkit patterns are Linux-only (diamorphine, adore-ng, reptile) |
| PersistenceScanner (13 types) | T1543, T1547, T1053, T1546 | 40% | Shell config: detects existence only, no content analysis; cron: user only |
| PersistenceMonitor | T1543, T1547 | 10% | Claims "ES-ready" but ZERO ES integration; polling-only; truly orphaned |
| RansomwareDetector + EntropyAnalyzer | T1486 | N/A | Truly orphaned (zero call sites) |
| AVMonitor | T1123, T1125 | N/A | Truly orphaned (zero call sites) |
| SigningVerifier (shared) | — | 50% | No entitlements check; no Team ID extraction; no revocation check |

### Scanner Bug Details (for fixing)

**BROKEN — must rewrite or remove:**
1. **TCCMonitor**: SIP prevents reading TCC.db on any modern Mac. sqlite3 CLI output parsing assumes pre-macOS-13 schema. Baseline has no persistence (lost on restart). **Fix: Use ES file events or private TCC APIs, not direct DB reads.**
2. **NetworkAnomalyDetector**: macOS `netstat -anp tcp` has no PID column. `scanCurrentConnections()` returns empty or wrong data. `recordConnection()` (beaconing input) has zero call sites — dead code. CV threshold 0.3 flags NTP/CloudKit/Slack as beaconing. **Fix: Use NEFilterDataProvider connection data via XPC, not netstat.**
3. **PersistenceMonitor**: `processFileEvent()` is never called by ES extension. Polling-only, not event-driven. Diff reports `pid: 0, processName: "unknown"` for all changes. **Fix: Wire to ESClient events or delete.**

**SIGNIFICANT BUGS — fix in place:**
4. **EventTapScanner line ~42**: Checks `tap.flagsMask` instead of `tap.eventsOfInterest` for flagsChanged events — misses keyboard-only taps. Known benign list has only 5 entries; needs Karabiner, Alfred, 1Password, BetterTouchTool, Keyboard Maestro, etc.
5. **LOLBinDetector**: Only checks direct parent PID (`getParentPID(pid)` once). Attack chains like `Safari→bash→curl→python3` only see `bash→curl`. Need recursive ancestry. Also: 33 entries, not 40+.
6. **ProcessIntegrityChecker**: `proc_regionfilename()` iterates 10K addresses × 0x1000 step = first 40MB of address space. Real processes have 50-200K regions spanning TB of virtual space. **Fix: Use `task_info(TASK_DYLD_INFO)` to get dyld_all_image_infos for loaded dylib list.**
7. **KextAnomalyDetector**: Rootkit patterns include Linux-only names (diamorphine, adore-ng, reptile, jynx). Replace with macOS-specific: Fruitfly, ThiefQuest, ZuRu, CDRThief, Shlayer.
8. **StealthScanner**: Emond check is dead code (daemon removed macOS 10.11). SUID scan limited to 5 dirs, misses /opt/, /usr/local/sbin, home dirs.
9. **CredentialAccessDetector**: Browser cookie "theft" triggers on every Chrome launch (DB modified = flagged). Script interpreter detection flags `python3 -c "print('keychain')"`.
10. **SupplyChainAuditor**: Pip typosquatting strips pattern prefixes but never verifies base package exists on PyPI. Xcode plugin detection is obsolete (plugins disabled since Xcode 9).
11. **SigningVerifier**: Only checks signature validity, not entitlements, Team ID, or revocation. `SecStaticCodeCheckValidity` with empty flags skips hardened runtime check.
12. **FileSystemBaseline**: Skips files >50MB silently. No symlink handling. Unlimited recursion (no depth guard). Baseline stored in user-writable location (attacker can overwrite).
13. **PersistenceScanner+Shell**: Detects shell config FILES exist but never reads content. Can't distinguish clean `.zshrc` from one containing `curl|bash`.

**CODE QUALITY ISSUES:**
- 6-8 identical copies of `getRunningPIDs()`/`getProcessPath()`/`getParentPID()` across scanner files — extract to shared helper
- 3 files exceed 300-line limit: ThreatScanView (421), CredentialAccessDetector (388), StealthScanner (368)
- Zero test files for IrisSecurity (every other package has tests)

### Priority Fix Order (REVISED after deep audit)
1. **P0**: Add IrisSecurity to pbxproj + wire HomeView → SecurityHubView (unblocks everything)
2. **P0**: Rewrite NetworkAnomalyDetector to use NEFilter connection data via XPC (not netstat)
3. **P0**: Rewrite TCCMonitor to use ES file events or remove it
4. **P0**: Fix EventTapScanner flagsMask bug + expand benign list
5. **P0**: Fix LOLBinDetector: recursive ancestry + real LOLBin count
6. **P1**: Fix ProcessIntegrityChecker: use task_info(TASK_DYLD_INFO) instead of proc_regionfilename
7. **P1**: Fix KextAnomalyDetector: replace Linux rootkit names with macOS-specific
8. **P1**: Extract shared ProcessEnumeration helper (deduplicate 6-8 copies)
9. **P1**: Add shell config content analysis to PersistenceScanner
10. **P1**: Fix SigningVerifier: add entitlements + Team ID extraction
11. **P2**: Fix StealthScanner: remove emond, expand SUID scan dirs
12. **P2**: Fix CredentialAccessDetector: filter browser cookie FPs
13. **P2**: Fix SupplyChainAuditor: remove obsolete Xcode plugin check
14. **P2**: Wire PersistenceMonitor to ES extension or delete it

=== BUGS ===

### View Layer (IrisSecurity/Views/)

**V1. No task cancellation in any security view**
All 7 views launch `.task {}` blocks that run scanners but never cancel on dismiss:
- `ThreatScanView.swift:31` — runs 11 scanners, no cancellation
- `PersistenceView.swift:27` — runs PersistenceScanner.scanAll() (13 subscans)
- `EventTapView.swift:25` — runs EventTapScanner.scan()
- `DylibHijackView.swift:25,46` — `.onChange(of: scanTarget)` spawns NEW tasks without cancelling old ones → unbounded task accumulation
- `FileIntegrityView.swift:35` — runs FileSystemBaseline checks
- `SupplyChainView.swift:29` — runs SupplyChainAuditor.auditAll()
- `SecurityDashboardView.swift:38,50` — refresh button spawns parallel SecurityAssessor runs
**Impact**: Resource leaks, dozens of concurrent scanner tasks on rapid navigation.

**V2. No error handling on scanner calls**
- `ThreatScanView.swift:163-226` — 11 `await Scanner.shared.scan()` calls with zero try/catch. One scanner failure aborts entire scan silently.
- `PersistenceView.swift:130` — `await PersistenceScanner.shared.scanAll()` unchecked. Permission denied on /Library/SystemExtensions/db.plist → spinner forever.
- `EventTapView.swift:93` — `await EventTapScanner.shared.scan()` unchecked.
- `SupplyChainView.swift:128` — `await SupplyChainAuditor.shared.auditAll()` unchecked.
**Impact**: Stuck UI, silent failures, scan appears to complete with partial results.

**V3. ThreatScanView count/filter mismatch**
`ThreatScanView.swift:63-67` — supply chain findings counted in severity badge totals but the filter toggle on line 82 applies different logic to the displayed list. Badge says "3 critical" but list shows different count.

**V4. ProcessAnomaly timestamp skew**
`ProcessAnomaly.swift:49` — `timestamp: Date = Date()` default means anomalies from a multi-second scan get spread across time instead of sharing one scan-start timestamp. Results appear out of order.

### Extension Layer

**E1. TLSSession use-after-free**
`TLSSession.swift:73-110` — `retainedRef = Unmanaged.passRetained(self)` prevents dealloc, but `close()` calls `retainedRef?.release()` (line ~110) while SSLSetIOFuncs callbacks registered at line ~68 may still fire from other threads. Dangling pointer in concurrent scenarios.
**Fix**: Guard callbacks with `isClosing` flag checked before dereferencing, or ensure SSLClose() blocks all pending callbacks.

**E2. TLSSession+IOCallbacks write hang**
`TLSSession+IOCallbacks.swift:54` — `writeToFlow()` uses `DispatchSemaphore.wait(timeout: .now() + .seconds(10))` on SSL queue. If flow.write callback is delayed (network buffer full, flow closing), SSL queue thread blocks 10 seconds. All TLS operations for that session halt.
**Fix**: Replace semaphore with async continuation.

**E3. UDP flow reader never stops**
`AppProxyProvider.swift:142-176` — `relayUDPFlow()` schedules 5-minute timeout that closes flow, but recursive `readLoop()` never checks if flow is closed. After timeout fires, readLoop retries indefinitely → memory leak + CPU spin.
**Fix**: Guard readLoop with `isClosed` check.

**E4. DNS TCP frame parsing — no bounds check**
`DNSProxyProvider+FlowHandlers.swift:~123` — reads 2-byte big-endian length prefix, computes `msgLength`, then slices `buffer[2..<(2 + msgLength)]` without validating `msgLength > 0` or `msgLength <= buffer.count - 2`. Malformed DNS query can crash extension with out-of-bounds access.
**Fix**: Add `guard msgLength > 0, buffer.count >= 2 + msgLength`.

**E5. DNS UDP datagram — no minimum size check**
`DNSProxyProvider+FlowHandlers.swift:~44` — `processDNSDatagram()` passes datagram directly to parser without verifying `datagram.count >= 12` (DNS header minimum). 1-byte datagram crashes parser.
**Fix**: Add `guard datagram.count >= 12`.

**E6. ExtensionDoHClient direct DNS fallback is unencrypted**
`ExtensionDoHClient.swift:164-228` — `directDNSFallback()` sends plain UDP DNS to `8.8.8.8:53`. No validation, no DNSSEC, no encryption. Spoofable on hostile networks. Also: 3-second timeout races with connection state handler, potentially cancelling connection after callback already fired.
**Fix**: Remove plain DNS fallback or add DNSSEC validation.

### XPC Store Layer

**X1. Timer not stopped on connection invalidation**
All three stores have `handleConnectionInvalidated()` that does NOT call `stopRefreshTimer()`:
- `DNSStore+XPC.swift:54-59`
- `ProxyStore+XPC.swift:56-62`
- `SecurityStore+XPC.swift:66-71`
Timer fires forever on dead connection, calling refresh on nil proxy → silent error loop, wasted CPU.
**Fix**: Add `stopRefreshTimer()` to every `handleConnectionInvalidated()`.

**X2. No reconnection on extension restart**
`ProxyStore+XPC.swift:64-71`, `DNSStore+XPC.swift`, `SecurityStore+XPC.swift` — `handleConnectionInterrupted()` sleeps 1s then retries `refreshStatus()`, but never calls `disconnect()` + `connect()`. If extension crashed and restarted, `xpcConnection` is permanently stale.
**Fix**: Call `disconnect()` then `connect()` in interruption handler.

**X3. XPC handlers set after resume**
`SecurityStore+XPC.swift:27-52` — `invalidationHandler` and `interruptionHandler` closures are set, but `connection.resume()` is called before they're fully wired. If connection invalidates between resume and handler assignment, handlers won't fire and app silently loses connection.
**Fix**: Set handlers before `connection.resume()`.

**X4. RelayState TOCTOU in MITM relay**
`FlowHandler+MITMRelay.swift:~43` — checks `state.hasRequest` outside lock, then parses HTTP, then calls `state.markRequestCaptured()`. Between check and mark, concurrent relay task can append data or corrupt parse state. HTTP response could be parsed as request.
**Fix**: Make check+parse+mark atomic, or parse under the lock.

### Architectural Issues

**A1. SecurityAssessor only runs 8 of 30 checks**
`SecurityAssessor.swift` — `assess()` calls only `SystemSecurityChecks.runAll()` (8 checks: SIP, FileVault, Gatekeeper, etc.). None of the 18 threat detection scanners are called. ThreatScanView runs 11 scanners as inline workaround, but SecurityAssessmentStore grade is based on 8 system checks only.
**Impact**: Security grade ignores all APT detection results.

**A2. PersistenceScanner+System marks ALL cron jobs suspicious**
`PersistenceScanner+System.swift:22,46` — every cron entry gets `isSuspicious: true, suspicionReasons: ["Active cron job"]`. Legitimate backup scripts, log rotations flagged as threats.
**Fix**: Only flag cron jobs with suspicious content (network calls, encoded strings, /tmp paths).

### Scanner Logic Bugs (see also "Scanner Bug Details" section above)

**S1. CredentialAccessDetector wrong vnode struct access**
`CredentialAccessDetector.swift:154-161` — uses `PROC_PIDFDVNODEPATHINFO` but accesses struct member path that may not match the actual `vnode_fdinfowithpath` layout. Risk of reading garbage data or crash.

**S2. XPCServiceAuditor shell wrapper misidentification**
`XPCServiceAuditor.swift:85-86` — extracts binary from `plist["Program"]` or first element of `ProgramArguments`, but `ProgramArguments` might be `["sh", "-c", "malicious command"]`. Reports "sh" as the audited binary instead of the actual payload.

**S3. AuthorizationDBMonitor string-contains check**
`AuthorizationDBMonitor.swift:73` — checks if rule *contains* string "allow" which matches "disallow", "allowInherited", etc. Needs exact match or type-safe plist parsing.

**S4. FileSystemBaseline no depth guard**
`FileSystemBaseline.swift:171` — directory enumerator has no depth limit. Deep symlink trees or deliberately nested directories cause scan to hang.

**S5. DyldEnvDetector collects all env vars before filtering**
`DyldEnvDetector.swift:244-247` — reads entire process environment then filters for DYLD_ prefix. Wastes memory on processes with large environments. Minor but unnecessary.

### Round 2 Audit — DNS Parsing (CRITICAL)

**D1. DNS TCP buffer unbounded growth — OOM crash**
`DNSProxyProvider+FlowHandlers.swift:122-128` — TCP DNS framing reads 2-byte length prefix (`msgLength`) but never validates the value. A malicious or malformed TCP DNS message claiming `msgLength = 65535` (or larger via repeated appends) causes `buffer` to grow unbounded while waiting for `2 + msgLength` bytes that may never arrive. Repeated connections can exhaust extension memory.
**Fix**: Cap `msgLength` to 65535 (DNS max per RFC 1035 Section 4.2.1: "Messages sent over TCP connections use server port 53. The message is prefixed with a two octet length field... restricting messages to 65535 octets."). Discard and reset buffer if exceeded:
```swift
let msgLength = Int(buffer[0]) << 8 | Int(buffer[1])
guard msgLength > 0, msgLength <= 65535 else { buffer.removeAll(); break }
guard buffer.count >= 2 + msgLength else { break }
```

**D2. DNS skipDNSName missing bounds check — out-of-bounds read**
`DNSProxyProvider+DNSHelpers.swift` (extension-side parser) — `skipDNSName()` reads a label length byte but doesn't validate that `offset + length` stays within `data.count` before advancing. A crafted DNS response with a label length byte of 63 (max label) near end of packet reads past buffer bounds.
**Fix**: After reading label length `len`, add `guard offset + Int(len) <= data.count else { return offset }` before advancing.

**D3. DNS compression pointer uses single byte instead of UInt16**
`DNSProxyProvider+DNSHelpers.swift` (extension-side parser) — Compression pointer handling uses `Int(b & 0x3F)` which only reads the low 6 bits of the FIRST byte. Per RFC 1035 Section 4.1.4, a compression pointer is a 14-bit value spanning TWO bytes: `((b0 & 0x3F) << 8) | b1`. Current code ignores the second byte entirely, producing wrong offsets for any pointer where the second byte is nonzero.
**Fix**: Read full 14-bit pointer:
```swift
if b & 0xC0 == 0xC0 {
    guard offset + 1 < data.count else { return offset }
    let pointer = Int(b & 0x3F) << 8 | Int(data[offset + 1])
    // use pointer, advance offset by 2
}
```

**D4. SERVFAIL response echoes raw query bytes**
`DNSProxyProvider+DNSHelpers.swift:buildServfailResponse(for:)` — constructs a SERVFAIL by copying the first 12 bytes of the original query as the response header, setting RCODE=2. However, it doesn't validate that the query is well-formed before echoing it. If the original query was malformed or adversarial, those bytes are sent back to the client unmodified except for flags.
**Fix**: Validate minimum 12-byte header, zero QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT in response, or build a minimal synthetic SERVFAIL from just the transaction ID.

**D5. No maximum DNS response size check**
`DNSProxyProvider+FlowHandlers.swift:59,139` — DoH response `responseData` from `dohClient.query()` is forwarded to the client without size validation. A compromised or malicious DoH server could return a multi-megabyte response. For UDP, this would be truncated by the OS, but for TCP (line 151-155) it's written directly with a 2-byte length prefix that wraps at 65535.
**Fix**: Validate `responseData.count <= 65535` before forwarding. For UDP, validate `responseData.count <= 4096` (practical UDP DNS limit).

### Round 2 Audit — Memory Safety (HIGH)

**M1. proc_fdinfo buffer misalignment — heap overflow**
`CredentialAccessDetector.swift:134-144` — `proc_pidinfo(pid, PROC_PIDLISTFDS, ...)` returns the number of **bytes** written, not the number of structs. The code does:
```swift
let fdCount = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
let buffer = UnsafeMutablePointer<proc_fdinfo>.allocate(capacity: fdCount / MemoryLayout<proc_fdinfo>.size)
```
If `fdCount` is not evenly divisible by `MemoryLayout<proc_fdinfo>.size` (8 bytes), integer division rounds DOWN, allocating fewer structs than needed. The second `proc_pidinfo` call writes `fdCount` bytes into the undersized buffer → heap overflow.
**Fix**: Use ceiling division: `(fdCount + MemoryLayout<proc_fdinfo>.size - 1) / MemoryLayout<proc_fdinfo>.size`. Also validate `fdCount > 0` before allocating.

**M2. MachOParser integer truncation on 32-bit**
`MachOParser.swift:40-52` — Fat binary parsing reads `UInt32` values for `offset` and `size` from fat_arch headers, then converts via `Int(UInt32(bigEndian: arch.offset))`. On a 32-bit process (unlikely on modern macOS but technically possible), `UInt32.max` (4GB) truncates when cast to `Int` (which is 32-bit), producing negative values. The subsequent `data[offset..<offset+size]` subscript uses these negative values → crash or out-of-bounds access.
**Fix**: Validate `offset + size <= data.count` AFTER conversion to Int, before slicing. This naturally catches truncation since `data.count` can't exceed memory.

**M3. Unbounded sysctl allocation — memory bomb**
`KextAnomalyDetector.swift:217-220` — calls `sysctl()` with `nil` buffer to get required size, then allocates exactly that size. If the kernel returns a pathologically large size (or if a TOCTOU race increases it between the size query and the data query), the allocation can be enormous.
**Fix**: Cap allocation at 64KB (`guard size <= 65536`). Kext list metadata should never exceed this. If it does, something is wrong.

### Round 2 Audit — Concurrency (MEDIUM)

**C1. ProxyXPCService.interceptionEnabled unguarded data race**
`ProxyXPCService.swift:~31` — `interceptionEnabled` is a `var Bool` read and written from multiple threads (XPC callbacks on arbitrary queues + FlowHandler on its own queue). All other mutable state in ProxyXPCService is guarded by `flowLock`, but `interceptionEnabled` is not.
**Fix**: Guard reads/writes with `flowLock`, or make it an atomic property.

**C2. capturedFlows.count read without lock**
`ProxyXPCService+XPCProtocol.swift:~19` — `getStatus()` reads `capturedFlows.count` to build the status dictionary without acquiring `flowLock`. This is called from XPC (arbitrary thread) while `capturedFlows` is mutated under `flowLock` on the flow handling path. Dictionary count read during concurrent mutation is undefined behavior in Swift.
**Fix**: Acquire `flowLock` before reading `capturedFlows.count` in `getStatus()`.

**C3. TLSSession.isClosed unguarded flag**
`TLSSession.swift:~107` — `close()` sets `isClosed = true` without any synchronization primitive. The SSL I/O callbacks on the SSL queue check `isClosed` to bail early. If `close()` runs on a different thread than the callbacks, the write to `isClosed` may not be visible (CPU cache coherence), or worse, may tear on architectures without atomic word writes.
**Fix**: Use `os_unfair_lock` or `NSLock` around `isClosed` access, or use `@Atomic` property wrapper.

### Round 2 Audit — Network Filter Logic (MEDIUM)

**N1. Rule port defaults to wildcard on parse failure**
`FilterDataProvider+Rules.swift` (or equivalent rule evaluation) — When a firewall rule specifies a port as a string that fails `UInt16()` conversion (e.g., "abc", "99999"), the rule matcher treats it as port 0, which may match wildcard rules. A rule intended to block port "http" (non-numeric) silently matches nothing or everything depending on wildcard semantics.
**Fix**: Reject rules with non-numeric port values at rule creation time. Return parse error to UI.

**N2. Single eviction on maxConnections overflow**
`FilterDataProvider+FlowHandling.swift:89-95` — When `connections.count > maxConnections`, only ONE connection is evicted (the oldest). If a burst of connections arrives simultaneously (e.g., browser opening 20 tabs), each new connection only evicts one, so the dictionary temporarily grows to `maxConnections + burst - 1` before stabilizing. With `maxConnections = 10000` and a burst of 100, dictionary hits 10099.
**Fix**: Evict in batch — remove oldest 10% when threshold exceeded:
```swift
if connections.count > Self.maxConnections {
    let evictCount = Self.maxConnections / 10
    let oldest = connections.sorted { $0.value.lastActivity < $1.value.lastActivity }.prefix(evictCount)
    for (id, _) in oldest {
        connections.removeValue(forKey: id)
        flowToConnection = flowToConnection.filter { $0.value != id }
    }
}
```

### Round 2 Audit — False Positives (NOT bugs)

These were flagged by audit agents but confirmed as correct after analysis:

**FP1. ObjectIdentifier(flow) use-after-free** — NEFilterFlow objects are retained by the NetworkExtension framework for the entire lifetime of the flow. `ObjectIdentifier` is stable while the object exists. Not a bug.

**FP2. peekInboundBytes = Int.max** — Standard Apple pattern for content filter providers. The kernel does NOT buffer Int.max bytes; it streams data via handleInboundData/handleOutboundData callbacks. Documented in NEFilterDataProvider headers.

**FP3. ConnectionTracker lost updates on value type** — `connections[connectionId] = tracker` after mutation looks like it could lose concurrent updates, but all access is guarded by `connectionsLock`. Sequential calls under the same lock read the latest value. Not a bug.

**FP4. audit_token_to_pid >= 24 bound** — PID is at index 5 of the audit_token_t (8 x UInt32). Index 5 starts at byte offset 20 and ends at 24. The `>= 24` guard is the correct minimum. Not a bug.

**FP5. TLS verify_block calling complete(true)** — The proxy's NWConnection to real servers accepts all certificates because we ARE the MITM. This is by design — the proxy validates the real server cert separately and presents its own generated cert to the client. Accepting all certs on the server-facing connection is correct MITM behavior.

---

## Round 3 Audit (Deep Security Audit — 10 Parallel Agents)

Launched 10 specialized agents. 3 completed full reports, 7 hit rate limits after
reading all relevant files but before writing reports. Findings below are from
the 3 completed agents plus observations from partial agent file reads.

### Round 3 — TLS MITM / Proxy (CRITICAL) — 21 NEW bugs

**P1. SSLWrite infinite loop on errSSLWouldBlock (HIGH)**
`TLSSession.swift`: `writeEncrypted()` calls `SSLWrite` in a while loop on
`errSSLWouldBlock`. If the ring buffer is full and no reader drains it, this
loops forever, burning CPU and blocking the flow handler thread.
**Fix**: Add max retry count or backoff, or make the ring buffer grow.

**P2. Double-resume risk in waitForData continuation (HIGH)**
`TLSSession.swift`: `waitForData()` stores continuation, and both `feedData()`
and `close()` can resume it. If close() races with feedData(), double-resume
crashes the process.
**Fix**: Guard continuation with a lock + nil-check-then-set pattern.

**P3. close() not thread-safe (MEDIUM)**
`TLSSession.swift`: `close()` calls `SSLClose()` and nils out `sslContext`
without holding the lock. Concurrent `readDecrypted`/`writeEncrypted` can race.
**Fix**: Hold the lock for all SSLContext access.

**P4. TLS handshake never times out (MEDIUM)**
`TLSSession.swift`: `performHandshake()` loops calling `SSLHandshake()` with
no timeout. Malicious server can hold the handshake open forever.
**Fix**: Add deadline, abort after 10s.

**P5. startFlowReader called multiple times (LOW)**
`TLSSession.swift`: No guard against calling `startFlowReader()` more than once,
which would spawn duplicate read tasks.

**P6. Certificate cache eviction is not LRU (MEDIUM)**
`TLSInterceptor.swift`: Extension-side cert cache uses `removeAll()` when full
instead of evicting LRU entries. Causes cache thrashing under load.
**Fix**: Use BoundedCache like app-side code.

**P7. Keychain pollution from createIdentity (HIGH)**
`TLSInterceptor+CertBuilder.swift`: `createIdentity()` adds a cert+key to
keychain, queries back the identity, then deletes. If the delete fails (crash,
timeout, etc.), orphaned keychain items accumulate forever.
**Fix**: Use in-memory identity creation, or add cleanup-on-launch.

**P8. buildInteger doesn't handle negative values (LOW)**
`TLSInterceptor+CertBuilder.swift`: ASN.1 INTEGER encoding doesn't prepend
0x00 byte when high bit is set. Could produce malformed certs for certain serial
numbers.

**P9. No IP SAN support in buildLeafExtensions (MEDIUM)**
`TLSInterceptor+CertBuilder.swift`: Only DNS SANs (GeneralName type 2) are
generated. Connections to IP addresses (e.g., `https://192.168.1.1`) will get
cert errors because IP SANs (GeneralName type 7) aren't emitted.
**Fix**: Detect IP vs hostname, emit type 7 for IPs.

**P10. UTCTime only valid until 2049 (LOW)**
`TLSInterceptor+CertBuilder.swift`: Uses UTCTime for certificate validity dates.
Per X.509, dates >= 2050 must use GeneralizedTime. Won't matter until 2049.

**P11. extractSubjectName no bounds-check during DER parsing (HIGH)**
`TLSInterceptor.swift`: `extractSubjectName()` parses DER from the real server
cert. No bounds checking — malformed cert from a malicious server could crash
the extension via out-of-bounds read.
**Fix**: Validate every offset before indexing.

**P12. Certificate cache lookup and insert race (MEDIUM)**
`TLSInterceptor.swift`: `getCertificate()` checks cache, misses, generates cert,
inserts. Two concurrent requests for the same host can both miss and both
generate, wasting keychain operations.
**Fix**: Use a per-host lock or in-flight request map.

**P13. Port 443 hard-coded as only HTTPS port (MEDIUM)**
`AppProxyProvider.swift`: `handleNewFlow` checks `port == 443` to route to HTTPS
handler. Port 8443, 4443, etc. are treated as plain TCP, missing TLS interception.
**Fix**: Detect TLS by ClientHello byte pattern (0x16 0x03), not port number.

**P14. UDP flow relay writes back to same flow — FUNDAMENTALLY BROKEN (HIGH)**
`AppProxyProvider.swift`: `handleUDPFlow()` reads datagrams and writes responses
back to the same NEAppProxyUDPFlow. NEAppProxyUDPFlow is NOT a socket — you
can't relay through it to a real server. The relay would just echo back.
**Fix**: Create a NWConnection to the real server for UDP relay, or drop UDP
interception entirely.

**P15. Only first HTTP request/response captured per connection (HIGH/design)**
`FlowHandler.swift`: HTTP parsing runs only on the first chunk of data in each
direction. HTTP/1.1 pipelining and keep-alive connections send multiple requests
on the same flow. After the first, all subsequent requests are invisible.
**Fix**: Parse continuously, accumulating partial buffers.

**P16. RelayState request buffer grows without bound (MEDIUM)**
`FlowHandler.swift`: `requestBuffer` in RelayState accumulates all request data
for HTTP parsing but is never truncated. A 1GB upload would OOM the extension.
**Fix**: Cap buffer at 64KB, stop accumulating after first parse.

**P17. receiveFromServer timeout task leaks — double-resume risk (MEDIUM)**
`FlowHandler.swift`: `receiveFromServer()` creates a timeout Task that resumes
the continuation. If the real response arrives AND the timeout fires, both try
to resume the same continuation.
**Fix**: Use the locked-boolean pattern like DoH client.

**P18. Passthrough/HTTP relay don't close flow on server disconnect (MEDIUM)**
`FlowHandler.swift`: When the server side disconnects, the relay stops reading
from server but doesn't close the client flow. Client sees a hang.
**Fix**: Cancel the client flow when server disconnects.

**P19. HTTP request smuggling via duplicate Content-Length (HIGH/security)**
`HTTPParser+RequestParsing.swift`: If a request has two Content-Length headers
with different values, the parser uses whichever it encounters first. A proxy
that interprets the second value differently would see different request
boundaries. Classic CL-CL desync.
**Fix**: Reject requests with multiple differing Content-Length headers (RFC 7230 3.3.3).

**P20. Chunked encoding size overflow (MEDIUM)**
`HTTPParser+RequestParsing.swift`: Chunk size parsed with `UInt64(hex, radix: 16)`
but no cap. A malicious chunk size like `FFFFFFFFFFFFFFFF` would cause the parser
to try reading an impossibly large body.
**Fix**: Cap chunk size at 16MB.

**P21. getFlows serializes ALL flows on every poll (HIGH/performance)**
`ProxyXPCService+FlowManagement.swift`: `getFlows()` JSON-encodes every active
flow on every 2-second XPC poll. With 500 active flows, this is 500 JSON encodes
every 2 seconds. Kills proxy performance.
**Fix**: Send only delta (new/changed flows since last poll).

### Round 3 — Endpoint Security (CRITICAL) — 17 findings

**ES1. Endpoint Security is ENTIRELY STUBBED (CRITICAL)**
`ESClient.swift`: The entire ES client is stubbed. Zero `es_subscribe` calls,
zero event monitoring. ALL process data comes from polling sysctl (`KERN_PROC`).
This means:
- No file operation events (T1005, T1041, T1486 undetected)
- No process execution events (T1059, T1106 undetected)
- No kext loading events (T1547.006 undetected)
- No code injection events (T1055 undetected)
- Short-lived processes (~80% of attacker tools) completely invisible
This is the single biggest gap in Iris's detection capability.

**ES2. ESProcessInfo vs ProcessInfo model mismatch (CRITICAL)**
`ESXPCService.swift` encodes `ESProcessInfo` structs. App-side `ProcessStore`
decodes `ProcessInfo` structs. Different field names (e.g., `processPath` vs
`path`). XPC data would never decode correctly if ES were actually sending data.
**Fix**: Unify models or add explicit CodingKeys.

**ES3. ISO8601 date encoding/decoding mismatch (CRITICAL)**
Extension uses `.iso8601` JSONEncoder date strategy. App side uses default (`.deferredToDate`).
Dates would decode to wrong values.
**Fix**: Both sides must use identical date strategy.

**ES4. No es_mute_process for own PID (HIGH)**
When ES is eventually wired up, Iris must mute its own PID to prevent infinite
recursion (Iris monitors itself monitoring itself). Without this, the extension
will generate events about its own monitoring, potentially crashing or creating
feedback loops.

**ES5. No es_retain_message for async processing (HIGH)**
The stubbed callback doesn't call `es_retain_message()`. When real ES events are
processed async (dispatched to another queue/task), the message pointer becomes
invalid — use-after-free.

**ES6. Self-capture in ES callback (HIGH)**
The callback closure captures `self` strongly. ES callbacks must be lightweight
and non-blocking. A strong self-capture that does significant work risks
deadlocking the ES subsystem.

**ES7. XPC continuation can hang forever (HIGH)**
`getProcesses()` uses `withCheckedContinuation` for the XPC reply. If the XPC
connection drops before the reply arrives, the continuation never resumes —
the caller hangs forever.
**Fix**: Add timeout wrapper, or use interruption handler to resume with error.

**ES8. Missing critical ES events (HIGH)**
Even when ES is wired up, the code only subscribes to `ES_EVENT_TYPE_NOTIFY_EXEC`.
Missing: `ES_EVENT_TYPE_NOTIFY_OPEN`, `ES_EVENT_TYPE_NOTIFY_WRITE`,
`ES_EVENT_TYPE_NOTIFY_RENAME`, `ES_EVENT_TYPE_NOTIFY_UNLINK`,
`ES_EVENT_TYPE_NOTIFY_KEXTLOAD`, `ES_EVENT_TYPE_NOTIFY_MMAP`,
`ES_EVENT_TYPE_NOTIFY_SIGNAL`. These are essential for:
- File integrity monitoring
- Ransomware detection
- Code injection detection
- Persistence installation detection

**ES9. FileManager.fileExists per-process in computed property (HIGH/perf)**
`ProcessInfo` has a computed `icon` property that calls `FileManager.fileExists`
for each process row in the UI. With 400+ processes, that's 400+ stat() syscalls
every time the view redraws.
**Fix**: Cache the result or use a background task.

**ES10. No event batching/rate limiting (MEDIUM)**
When ES events are eventually flowing, there's no batching. A `find /` command
generates thousands of events per second. Without batching, the XPC pipe and
UI would be overwhelmed.
**Fix**: Buffer events, send batches every 100ms.

**ES11. No XPC reconnection logic (MEDIUM)**
If the XPC connection to the ES extension drops, there's no automatic reconnect.
ProcessStore would silently stop receiving data.
**Fix**: Add invalidation handler that reconnects after delay.

**ES12. No app-side code signing verification for ES XPC (MEDIUM)**
App-side `ProcessStore` connects to the ES extension without verifying the
extension's code signature. A rogue extension with the same Mach service name
could feed false process data.

**ES13. Short-lived processes invisible (MEDIUM/design)**
Sysctl polling at 2-second intervals misses processes that start and exit within
2 seconds. Most attacker tools (curl|bash, one-shot python scripts) are designed
to be short-lived. This is the fundamental limitation of polling vs ES events.

**ES14. ProcessStore not shared singleton in view (MEDIUM)**
Some views create new ProcessStore instances instead of using `.shared`,
resulting in duplicate XPC connections.

### Round 3 — Certificate Generation / ASN.1 (HIGH) — 9 findings

**CERT1. No IP address SAN support (HIGH)**
`TLSInterceptor+CertBuilder.swift` and `CertificateGenerator.swift`: Only DNS
SANs are generated. HTTPS connections to IP addresses will get TLS errors.
Both the extension-side and package-side cert generators share this gap.

**CERT2. No keyUsage extension on leaf certificates (HIGH)**
Generated leaf certs don't include the keyUsage extension (`digitalSignature`,
`keyEncipherment`). Some TLS implementations reject certs without proper
keyUsage, especially with RSA key exchange.

**CERT3. UTCTime will break in 2050 (LOW)**
Both implementations use UTCTime for all dates. X.509 requires GeneralizedTime
for years >= 2050. Not urgent.

**CERT4. CA certificate lacks pathLenConstraint (HIGH)**
Generated CA cert's basicConstraints extension has `CA:TRUE` but no
`pathLenConstraint:0`. Without this, the CA cert can sign intermediate CAs.
A compromised leaf could theoretically be used as a signing cert.
**Fix**: Add pathLenConstraint:0 to basicConstraints.

**CERT5. buildSubjectPublicKeyInfo double-wraps RSA key (HIGH)**
`TLSInterceptor+CertBuilder.swift`: The RSA public key is already a SEQUENCE
(per PKCS#1), then wrapped in another SEQUENCE for SubjectPublicKeyInfo. If
the input key data already includes the outer SEQUENCE, it gets double-wrapped,
producing a malformed certificate that clients will reject.
**Fix**: Check if key data already has SEQUENCE wrapper.

**CERT6. createIdentity leaks keychain items on crash (MEDIUM)**
Same as P7 above. The add-query-delete dance in createIdentity leaves orphaned
items if the process crashes between add and delete.

**CERT7. Race condition in getCertificate (MEDIUM)**
Same as P12 above. Two concurrent HTTPS connections to the same host both
miss the cache and both generate certificates.

**CERT8. SecRandomCopyBytes return value ignored (MEDIUM)**
Serial number generation calls `SecRandomCopyBytes` but doesn't check the
return value. If it fails (rare but possible), the serial number is all zeros,
which could cause cert collisions.

**CERT9. Two independent ASN.1 implementations (MEDIUM/tech debt)**
`TLSInterceptor+CertBuilder.swift` (extension) and `CertificateGenerator.swift`
(IrisCertificates package) both implement ASN.1 DER encoding from scratch. They
have diverged: the package version is more correct (proper tag handling), while
the extension version has the double-wrapping bug (CERT5). This duplication
guarantees bugs will be fixed in one place but not the other.
**Fix**: Consolidate into a single shared ASN.1 module.

### Round 3 — Partial Findings from Rate-Limited Agents

These agents read all relevant files but hit API rate limits before writing
their reports. Key observations from their file reads:

**IrisSecurity Scanners (51 files read)**
- SecurityAssessmentStore only calls SecurityAssessor.assess() which only runs
  SystemSecurityChecks.runAll() — 16 of 20 scanners never execute
- 6-8 duplicate `getRunningPIDs()` helpers across scanner files
- Zero unit tests for any scanner
- Multiple scanners >300 lines (violates project guidelines)

**App Stores + XPC (ExtensionManager, SecurityStore, ProxyStore, DNSStore)**
- ExtensionManager.cleanReinstallExtensions() only uninstalls network+endpoint,
  skips proxy+dns
- Proxy and DNS extension polling only checks XPC reachability, not actual
  extension health
- No retry logic on XPC connection failures across any store

**Nation-State Detection Gaps (DyldEnvDetector, LOLBinDetector, etc.)**
- DyldEnvDetector is the most thorough scanner (KERN_PROCARGS2 parsing,
  launchd plists, shell profiles, self-check)
- LOLBinDetector has 33 LOLBins (not 40+ as documented), parent-child
  analysis only goes 1 level deep
- NetworkAnomalyDetector beaconing analysis is dead code — macOS netstat
  doesn't provide PIDs, so the detector can't attribute network activity
  to processes

**WiFi/Disk/Satellite modules**
- These are utility/visualization modules, not security-critical
- DiskScanner correctly uses FileManager with proper error handling
- WiFiStore shells out to system_profiler — no injection risk (hardcoded path)

**DNS Extension + Parser (both extension and package side)**
- App-side DNSMessageParser has proper compression pointer handling with
  jump limit (10 max), correct bounds checks
- Extension-side DNS parser (parseDNSQueryInfo) much simpler, uses 16-bit
  compression mask (incorrect — should be 14-bit, only top 2 bits)
- Two completely independent DNS parsers that could diverge

**Network Extension**
- XPC code signing verification is correct (SecCodeCheckValidity with team ID)
- FilterDataProvider correctly evaluates rules before tracking flows
- Entitlements are overly broad: network extension has dns-proxy,
  packet-tunnel-provider, app-proxy-provider, relay — only needs
  content-filter-provider

### Round 3 — Entitlements Issues (from partial agent read)

**ENT1. Network extension has 7 NE entitlements, needs 1 (MEDIUM)**
`IrisNetworkExtension.entitlements`: Lists dns-proxy, url-filter-provider,
packet-tunnel-provider, dns-settings, app-proxy-provider, content-filter-provider,
relay. Only `content-filter-provider` is used. The extras widen the attack surface
for no benefit.
**Fix**: Remove all except content-filter-provider.

**ENT2. Missing audit of other extension entitlements (DEFERRED)**
The entitlements audit agent died before reading proxy/dns/endpoint entitlements.
Need separate audit of those files.

### Round 4 — Deep Security Audit (8 Specialized Agents, Full Codebase)

8 agents read every file in every package and extension. ~60 genuinely new findings
below (excluding duplicates with Rounds 1-3 above).

#### IrisNetwork — Enrichment & Firewall (16 new findings)

**NET1. IPv4-mapped IPv6 not detected as private (MEDIUM/security)**
All 7 enrichment services (GeoIP, InternetDB, GreyNoise, AbuseIPDB, etc.) check
for private IPs with string prefix matching (`hasPrefix("fc")`, `hasPrefix("fd")`).
Missing: IPv4-mapped IPv6 like `::ffff:192.168.1.1`, IPv6-embedded IPv4 like
`::192.168.1.1`. Attacker using mapped addresses leaks metadata to external APIs.
**Fix**: Parse with Foundation `IPv4Address`/`IPv6Address`, not string prefixes.

**NET2. GreyNoise rate limit race condition (MEDIUM/concurrency)**
`GreyNoiseService.swift:156-199` — `requestCount += 1` and `resetDailyCountIfNeeded()`
access mutable state from multiple async contexts. The actor isolation is declared
but `requestCount` reads/writes interleave across `fetchSingle()` and `isAvailable()`.
Same issue in AbuseIPDBService.
**Fix**: Ensure all state mutation happens within the actor's serial executor.

**NET3. Enrichment data not persisted — lost on restart (HIGH/data loss)**
`SecurityStore+DataRefresh.swift:86-142` — All enrichment results (geolocation,
threat scores, CVEs) exist only in `@Published var connections` (in-memory). App
crash or force-quit = all enrichment lost. Re-enrichment on restart hits API rate
limits (GreyNoise: 100/day).
**Attack**: APT triggers app restart, enrichment quota exhausted, new connections
appear "benign" because enrichment silently fails.
**Fix**: Add SQLite or UserDefaults persistence for enrichment cache.

**NET4. Shodan URL injection via unvalidated remoteAddress (MEDIUM/security)**
`IPDetailPopover+ThreatSection.swift:91` — Constructs Shodan URL from
`connection.remoteAddress` without validating it's actually an IP.
If extension is compromised and sends `"https://evil.com?x="` as remoteAddress,
the URL opens the attacker site.
**Fix**: Validate IP format before URL construction.

**NET5. batchEnrich() concurrent tasks exceed rate limits (HIGH/design)**
`IPEnrichmentService.swift:198-215` — Chunk size 20 × 4 services = 80 concurrent
HTTP requests per chunk. GreyNoise has 100/day limit. 2 chunks = blocked.
**Fix**: Per-service rate limiting queues, serial processing for rate-limited APIs.

**NET6. BoundedCache TTL uses `>` not `>=` (LOW/logic)**
`BoundedCache.swift:33` — `Date().timeIntervalSince(entry.insertedAt) > ttl` means
entries live 1 extra tick. Minor but stale threat intel could be served.
**Fix**: Change to `>=`.

**NET7. Sensitive headers copied to clipboard unredacted (HIGH/security)**
`HTTPRawDetailView.swift:172-188` — "Copy to Clipboard" copies raw HTTP including
Authorization, Cookie, X-API-Key headers verbatim. Clipboard readable by any process.
**Fix**: Redact sensitive headers, auto-clear clipboard after 30s.

**NET8. SecurityRule hostname matching logic fragile (MEDIUM/logic)**
`SecurityRule.swift:134-143` — Rule matching falls through from signingId to hostname
to IP in a confusing cascading `if` chain. Works by accident for some cases.
**Fix**: Simplify: `let ipMatches = ... || ...; let hostMatches = ...; if !ipMatches && !hostMatches { return false }`.

**NET9. Port validation silent failure (MEDIUM/logic)**
`SecurityRule.swift:146-150` — `UInt16(remotePort)` returns nil for "99999" (typo).
Rule silently never matches. User thinks rule is active.
**Fix**: Return false for invalid port values, log warning.

**NET10. No enrichment deduplication (MEDIUM/performance)**
`IPEnrichmentService.swift:178-220` — Rapid successive calls to `batchEnrich()` with
overlapping IPs send duplicate requests. No in-flight request tracking.
**Fix**: Add `inFlightRequests: Set<String>` with lock to coalesce.

**NET11. No threat correlation / composite scoring (IMPROVEMENT)**
Each enrichment service operates independently. No composite risk score combining
abuse score + scanner status + CVE count. Single signals are noisy; combined = signal.

**NET12. IPv6 sorting is lexicographic, not numeric (LOW/UI)**
`ProcessConnectionRow.swift:21-45` — IPv6 addresses sorted by string comparison.
`2001:db8::1` vs `2001:db8::10` produces wrong order.

**NET13. No XPC data integrity signature (IMPROVEMENT/defense-in-depth)**
Extension sends connection data via XPC without HMAC. Compromised extension can
inject fake connections. Add HMAC with shared secret.

**NET14. No XPC call timeout (LOW/resilience)**
`SecurityStore+DataRefresh.swift:68-75` — `withCheckedContinuation` for XPC call
has no timeout. Extension hang = app hang.

**NET15. Connection detail HTTP path no truncation guard (LOW/UI)**
Actually handled correctly by `lineLimit(1)` + prefix truncation. Not a bug.

**NET16. staleTimeout cleanup doesn't stop flow forwarding (LOW/design)**
`FilterDataProvider.swift:120-138` — Stale connections removed from tracking but
underlying NEFilterFlow not told to stop. Monitoring silently stops for idle flows
that become active again.

#### IrisProcess — Process Monitoring (8 new findings)

**PROC1. Off-by-one in KERN_PROCARGS2 parsing (CRITICAL/bug)**
`ProcessStore+DataFetch.swift:214-224` — After inner loop exits with
`offset == size` (end of buffer, no null terminator found), line 223 still
increments `offset += 1` to `size + 1`. Next iteration safely exits, but the
last argument is silently truncated if not null-terminated.
**Attack**: Attacker crafts malformed PROCARGS2 → argument containing injection
command (e.g., `curl|bash`) truncated, invisible to Iris.
**Fix**: Add `guard offset <= size else { return args }` after increment.

**PROC2. TOCTOU race in deletedBinary detection (CRITICAL/security)**
`ProcessInfo.swift:209-212` — `FileManager.default.fileExists(atPath:)` runs in
a computed property on every view refresh. Attacker spawns from `/tmp/malware`,
deletes binary, then replaces path with legitimate binary. Next refresh shows
no `deletedBinary` flag.
**Fix**: Store path existence at process creation time (from ES), not recomputed.

**PROC3. Code signing uses string matching, not crypto (HIGH/security)**
`ProcessStore+DataFetch.swift:250-254` — `isAppleSigned` determined by
`signingId?.hasPrefix("com.apple.") == true`. Spoofable by any dev certificate.
`isPlatformBinary` checks `flags & 0x0001` (CS_VALID) instead of `0x4000`
(CS_PLATFORM). ANY valid signature = "platform binary."
**Fix**: Use `SecStaticCodeCheckValidity` with proper CS flags and Apple CA chain.

**PROC4. Arbitrary argc < 256 cutoff (HIGH/bug)**
`ProcessStore+DataFetch.swift:205` — `guard argc > 0, argc < 256 else { return [] }`.
Processes with >255 arguments (deep env, build tools) silently lose all args.
Attacker can hide injection in argument 257+.
**Fix**: Remove arbitrary limit, parse all arguments, flag argc > 512 as suspicious.

**PROC5. Unsafe memory rebound without alignment check (MEDIUM/bug)**
`ProcessStore+DataFetch.swift:202-204` — `withMemoryRebound(to: Int32.self)` assumes
natural alignment. KERN_PROCARGS2 is word-aligned on macOS (safe in practice), but
no explicit validation.
**Fix**: Use `buffer.withUnsafeBytes { $0.load(as: Int32.self) }` instead.

**PROC6. Command injection risk in ManPageStore (MEDIUM/security)**
`ManPageStore.swift:153` — Process name from `process.name` passed to
`/usr/bin/man -w <command>`. Uses `Process()` with array args (no shell injection),
but `normalizeCommand()` at line 142 takes first alphanumeric component, losing
context. A process named `malware-v2` becomes `malware`.
**Fix**: Validate command against alphanumeric+underscore whitelist.

**PROC7. File existence in computed suspicionReasons (MEDIUM/performance)**
`ProcessInfo.swift:209` — `FileManager.default.fileExists()` called in computed
property = on every view refresh. 400 processes × file stat = 400 syscalls per
frame.
**Fix**: Cache result at ProcessInfo creation time.

**PROC8. No process baseline / no drift detection (IMPROVEMENT)**
No mechanism to detect "process was unsigned before, now signed" (hollowing) or
"process had different code hash 5 minutes ago." ES events would enable this.

#### IrisProxy + TLS MITM (7 new findings, excluding Round 3 duplicates)

**PROXY1. NSLock used across async suspension points (HIGH/concurrency)**
`TLSSession+IOCallbacks.swift:22-39` — `readBufferLock.lock()` acquired in
`consumeFromBuffer()` (called from SSL callback thread) AND in async
`waitForData()`. NSLock is a pthread_mutex that requires unlock on same thread.
If Swift runtime suspends async Task between lock/unlock, it may resume on a
different thread → undefined behavior.
**Fix**: Use `os_unfair_lock` for sync-only paths, actor isolation for async.

**PROXY2. No HTTP/2 or HTTP/3 detection or handling (HIGH/gap)**
`FlowHandler+MITMRelay.swift:43` — HTTP parser searches for `\r\n\r\n` only.
HTTP/2 uses binary framing (0x505249 magic + frames). After TLS ALPN negotiates
h2, all data is binary → parser returns nil forever → flow forwarded uninspected.
**Attack**: Attacker uses HTTP/2 for C2 — completely invisible to Iris.
**Fix**: Detect protocol from TLS ALPN, or disable h2 negotiation in MITM.

**PROXY3. No rate limiting on flow creation (MEDIUM/DoS)**
`AppProxyProvider.swift:73-85` — `handleNewFlow()` accepts every flow with no
rate limit. 10,000 concurrent connections = 10,000 FlowHandler tasks → OOM.
**Fix**: Limit to 1000 concurrent flows, reject excess.

**PROXY4. Flow leak on unhandled exceptions (MEDIUM/resource leak)**
`AppProxyProvider.swift:87-121` — Flow added to `activeFlows` before
`flow.open()`. If open fails, `removeFlow()` may not execute (e.g., Task
creation failure). Flow stays in tracking map forever.
**Fix**: Use defer pattern to ensure cleanup.

**PROXY5. Keychain operations not atomic — cert/key mismatch (MEDIUM)**
`TLSInterceptor+CertBuilder.swift:64-109` — Key added to keychain, then cert.
Crash between = orphaned key. Next generation with same UUID = mismatched pair.
**Fix**: Use unique labels, add cleanup-on-launch.

**PROXY6. Only first request/response captured (already P15 — confirmed HIGH)**
HTTP/1.1 keep-alive sends multiple request/response pairs per flow. After first
parse, all subsequent traffic invisible. This means ~80% of HTTP traffic through
persistent connections is uncaptured.

**PROXY7. Content-Length body extraction takes all remaining data (MEDIUM)**
`FlowHandler+Helpers.swift:56-74` — `extractRequestBody()` returns
`Data(buffer[bodyStart...])` instead of `Data(buffer[bodyStart..<bodyStart+contentLength])`.
Pipelined requests leak into wrong response body.

#### IrisDNS — DNS Monitoring (5 new findings, excluding duplicates)

**DNS1. No RDATA format validation on responses (HIGH/security)**
`DNSProxyProvider+Parsing.swift:48-104` — DoH responses forwarded without
validating RDATA format. Malformed RDATA (wrong length for A/AAAA records,
corrupt TXT data) can crash the extension parser.
**Fix**: Validate RDATA length matches expected for each record type.

**DNS2. Process name spoofing via bundle ID (HIGH/evasion)**
`DNSProxyProvider+FlowHandlers.swift:66` — Process name extracted as
`sourceAppSigningIdentifier.components(separatedBy: ".").last`. Attacker
creates app `com.evil.Finder` → DNS monitor shows "Finder" made the query.
Analyst thinks it's the legitimate Apple Finder.
**Fix**: Show full signing identifier, not just last component.

**DNS3. No query rate limiting (MEDIUM/DoS)**
`DNSProxyProvider.swift:22-24` — Memory-bounded to 10K queries, but no rate
limit on incoming queries/second. Malware flooding 1M queries/sec overwhelms
XPC JSON encoding (1000 objects × 200 bytes × 30 polls/min = 6MB/min XPC).
**Fix**: Drop queries exceeding 10K/sec.

**DNS4. TCP buffer no size limit (MEDIUM/DoS)**
`DNSProxyProvider+FlowHandlers.swift:106-120` — TCP DNS appends data to
`buffer` indefinitely. Partial messages never completing = unbounded growth.
**Fix**: Cap at 65535 bytes (DNS TCP max), reset on overflow.

**DNS5. ExtensionDoHClient arbitrary server (MEDIUM/if app compromised)**
App-side `DoHClient` accepts arbitrary `DoHServerConfig` with any URL. If app
is compromised, all DNS routes through attacker server. Extension-side is
protected (hardcoded server list).

#### IrisShared + Shared/ (5 new findings, excluding duplicates)

**SHARED1. Integer overflow in chunked encoding UInt→Int cast (CRITICAL)**
`HTTPParser+Streaming.swift:205,227` — `Int(chunkSize)` where chunkSize is UInt.
If UInt value > Int.max (e.g., `0xFFFFFFFFFFFFFFFF`), the cast wraps to negative.
`chunkEnd = crlfPos + 2 + (-1) + 2 = crlfPos + 3` passes bounds check, but
subsequent slice uses corrupted indices → out-of-bounds memory access.
**Fix**: Validate `chunkSize <= UInt(Int.max) - 4` before Int cast.

**SHARED2. Content-Length: Int.max causes infinite buffering (CRITICAL)**
`HTTPParser+RequestParsing.swift:78-80` — `Int("9223372036854775807")` succeeds.
Streaming parser waits for Int.max bytes → never reaches `.complete` state →
buffer capped at 16MB but parser stuck forever.
**Fix**: Reject Content-Length > 100MB.

**SHARED3. XPC ping continuation double-resume crash (HIGH/concurrency)**
`ExtensionManager+StatusChecking.swift:104-126` — `didResume` is a plain Bool,
not atomic. Timer callback and invalidation handler race to call
`continuation.resume()`. Both succeed → Swift fatal error (double resume).
**Fix**: Use NSLock + didResume, or use `withCheckedThrowingContinuation` with
proper cancellation.

**SHARED4. No rate limiting on XPC protocol calls (HIGH/DoS)**
All XPC protocols (`getConnections`, `getRules`, `getQueries`, `getFlows`)
have no rate limiting. Compromised app can spam millions of calls, saturating
extension thread pool and starving legitimate monitoring.
**Fix**: Add rate limiting in XPC service handlers.

**SHARED5. Missing connection invalidation on rejected XPC (MEDIUM/leak)**
`XPCService.swift:66-90` (Network Extension) — When code signing fails,
`shouldAcceptNewConnection` returns `false` but never calls
`newConnection.invalidate()`. Connection object leaks.
**Fix**: Add `newConnection.invalidate()` before `return false`.

#### IrisCertificates (6 new findings)

**CERT10. Forced type cast crash on keychain lookup (CRITICAL)**
`CertificateGenerator.swift:61` — `kSecValueRef as! SecIdentity` forced cast.
If keychain returns unexpected type (e.g., SecCertificate), this crashes.
**Fix**: Use `as?` with error handling.

**CERT11. Unmanaged<CFError> takeRetainedValue memory leak (HIGH)**
`CertificateGenerator.swift:43-48` — `error?.takeRetainedValue()` pattern
at multiple sites. If exception occurs between `takeRetainedValue()` and
usage, the CFError leaks. Multiple occurrences at lines 113, 148.
**Fix**: Use `takeUnretainedValue()` or `try?` pattern.

**CERT12. DER parseLength off-by-one (HIGH/security)**
`CertificateGenerator+Components.swift:193` — Bounds check is
`offset + numBytes < bytes.count` but loop reads `bytes[offset + 1 + i]`.
When `i = numBytes - 1`, access is at `offset + numBytes`. Should be
`offset + 1 + numBytes <= bytes.count`.
**Fix**: Correct bounds check.

**CERT13. No cert expiration validation in CertificateCache (MEDIUM)**
`CertificateCache.swift:60-83` — Cache checks TTL (1 hour) but never
checks if `SecCertificate.notAfter` has passed. Expired certs served
from cache → TLS handshake failures, user visible errors.
**Fix**: Add `SecCertificateCopyNotAfterDate` check on cache hit.

**CERT14. Serial number entropy — SecRandomCopyBytes unchecked (MEDIUM)**
`CertificateGenerator+ASN1.swift:6-11` — Return value of `SecRandomCopyBytes`
ignored. If it fails (rare), serial number is all zeros → cert collision.
**Fix**: Check return value, fallback to `arc4random_buf` on failure.

**CERT15. Typo: `storageFailer` in error enum (LOW)**
`CertificateStore.swift:253` — Should be `storageFailed`.

#### IrisWiFi (4 new findings)

**WIFI1. Command injection via airport preference setting (CRITICAL/security)**
`WiFiStore+Preferences.swift:96` — `process.arguments = [interfaceName, "prefs",
"\(key)=\(value)"]` with user-supplied `key` and `value`. Process() uses execve
(no shell), but no allowlist of valid preference keys. If airport binary has
argument parsing bugs, this is exploitable.
**Fix**: Allowlist of valid keys: `JoinMode`, `RememberRecentNetworks`, etc.

**WIFI2. system_profiler subprocess race + no timeout (HIGH)**
`WiFiStore+ModelBuilding.swift:13-56` — `fetchMCSAndNSS()` spawns
`system_profiler SPAirPortDataType -json` without atomic flag. Multiple threads
can spawn multiple system_profiler processes. No timeout → hung subprocess =
blocked thread forever.
**Fix**: Add atomic `isFetching` flag + 3-second timeout.

**WIFI3. WiFi power state TOCTOU (MEDIUM)**
`WiFiStore+Scanning.swift:17-20` — Checks `interface.powerOn()`, then
`interface.scanForNetworks()` on line 28. WiFi can be toggled off between
check and scan. Error is caught, but stale results returned.

**WIFI4. Airport output parsing loses values with `=` (MEDIUM)**
`WiFiStore+Preferences.swift:50` — Splits by `=` with `parts.count == 2`.
Values containing `=` (e.g., base64-encoded preferences) silently skipped.

#### IrisDisk (3 new findings)

**DISK1. Symlink traversal — follows symlinks recursively (HIGH/security)**
`DiskScanner.swift:166-201` — `contentsOfDirectory` returns symlinks as
regular items. `walkDirectory` follows them. Attacker creates
`/tmp/huge -> /System/Library` → scan traverses all of /System.
Symlink loops inflate sizes, recursive symlinks cause near-infinite scan.
**Fix**: Add `.skipsSymlinkDirectories` or check `isSymbolicLink` per URL.

**DISK2. No volume crossing check (MEDIUM/logic)**
Scan of `/` traverses into `/Volumes` (external drives, network shares).
Reported size includes external media, misleading for system disk analysis.
**Fix**: Compare `st_dev` to stay on same filesystem.

**DISK3. Cache stored in world-readable directory (MEDIUM/disclosure)**
`DiskUsageStore.swift:58-61` — `~/Library/Caches/disk_scan_cache.json` is
world-readable. Contains full file tree with names and sizes. Any process
can read the user's complete file inventory.
**Fix**: Use restricted permissions (0o600) or encrypted cache.

#### System Extensions — Cross-Cutting (4 new findings)

**EXT1. All XPC uses empty SecCSFlags — no strict validation (HIGH/security)**
All 4 extensions use `SecCSFlags()` (empty) for `SecCodeCheckValidity`.
Missing: `kSecCSStrictValidate` (strict checks), hardened runtime enforcement.
Allows verification to pass with entitlements disabled or code patched.
**Fix**: Use `SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckNestedCode)`.

**EXT2. No mutual XPC authentication (extension → app) (MEDIUM/security)**
Extensions verify connecting app's Team ID. But app doesn't verify extension's
identity. Rogue extension with same Mach service name = trusted by app.
**Fix**: App should verify extension code signature on XPC connection.

**EXT3. Rule matching allows unsigned binary to match signed rule (MEDIUM)**
`NetworkModels.swift:34-61` — If rule specifies signingId but connection has
no signingId (unsigned), falls back to path matching. Attacker renames binary
to match path of allowed signed app → rule matches, traffic allowed.
**Fix**: If rule has signingId, ONLY match by signingId, never fall back.

**EXT4. Relay timeout only closes write half (MEDIUM/leak)**
`FlowHandler+HTTPRelay.swift:27-32` — `flow.closeWriteWithError(nil)` on
timeout doesn't close read side. Client and server still reading from half-
closed flow → resource leak.
**Fix**: Call both `closeReadWithError` and `closeWriteWithError`.

#### App Layer — UI & Lifecycle (10 new findings)

**APP1. No crash recovery / state persistence (CRITICAL/security)**
`IrisApp.swift` — No crash recovery mechanism. App crash = all monitoring
state lost. No persistent record of what was being monitored, which rules
were active, or what threats were detected. Attacker triggers crash →
clean slate on restart.
**Fix**: Persist extension states, active rules, detection history to disk.

**APP2. Disable filter toggle with ZERO confirmation (CRITICAL/security)**
`SettingsView+NetworkExtension.swift:52-63` — Single toggle disables ALL
network filtering. No confirmation dialog, no audit log, no re-auth.
Malware with code injection into Iris could toggle this programmatically.
**Fix**: Show NSAlert with red warning, require explicit "Disable" click.

**APP3. Uninstall extension with ZERO confirmation (CRITICAL/security)**
`SettingsView+Helpers.swift:139-147` — Red "Uninstall" button with no
confirmation. Single click removes security monitoring entirely.
**Fix**: Show destructive confirm alert, require typing "UNINSTALL".

**APP4. No tamper detection / self-integrity checking (CRITICAL/security)**
No runtime signature verification on app binary or extension bundles. If Iris
is replaced with trojanized version, no detection. SecStaticCodeCheckValidity
exists in IrisSecurity's SigningVerifier but is NOT used in app layer.
**Fix**: Verify app + extension signatures on launch and periodically.

**APP5. No app lifecycle authentication (CRITICAL/security)**
No biometric re-auth when app returns from background. Attacker with physical
access opens Iris, disables extensions, steals API keys. No protection.
**Fix**: Use LAContext for Face ID/Touch ID on resume and destructive actions.

**APP6. API key stored in plaintext UserDefaults (MEDIUM/security)**
`SettingsView.swift:8-9` — `@AppStorage("abuseIPDBAPIKey")`. Any process can
read via `defaults read com.wudan.iris abuseIPDBAPIKey`.
**Fix**: Move to Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.

**APP7. No continuous monitoring for extension failures (MEDIUM/security)**
`SettingsView.swift:62-66` — Extension status checked ONLY on SettingsView
appear. If extension crashes while user is on another screen, no notification.
Network filter could be down for hours without user awareness.
**Fix**: Background polling every 30s with persistent banner on failure.

**APP8. No warning when extensions fail to install (MEDIUM/UX)**
`SettingsView+Helpers.swift:151-161` — Failed extension shows "Retry" button
with no explanation of why it failed. User may complete setup with zero
extensions loaded.
**Fix**: Show bright red alert overlay, block navigation until resolved.

**APP9. Metal shader no bounds check on button index (MEDIUM/GPU safety)**
`HomeRenderer+Shader.swift:344-355` — `u.hoveredButton` passed to
`renderButton()` without bounds check. Memory corruption in Metal code could
produce out-of-range index → GPU reads invalid memory.
**Fix**: Clamp `hoveredButton` to `[0, buttonCount)` in shader.

**APP10. Zero test coverage for app layer (IMPROVEMENT)**
No tests for HomeView, SettingsView, HomeRenderer, app lifecycle, navigation,
or state management. Combined with 0 tests for IrisSecurity (51 files), ~60%
of the codebase has no test coverage.

#### IrisSatellite — Metal Rendering (2 new findings)

**SAT1. Shader compilation failure has no fallback (MEDIUM)**
`Renderer+Setup.swift:47-60` — If Metal shader compilation fails, throws
error that crashes app. No graceful degradation to "rendering disabled" state.
**Fix**: Catch error, show placeholder view.

**SAT2. Frame semaphore value not validated (LOW)**
`Renderer+Setup.swift:34` — `DispatchSemaphore(value: configuration.maxFramesInFlight)`.
If `maxFramesInFlight <= 0`, semaphore behaves unexpectedly.
**Fix**: Guard `maxFramesInFlight > 0`.
