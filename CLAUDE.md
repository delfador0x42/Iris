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
