# Iris - AI Development Guide

## Quick Start

```bash
# Build
xcodebuild -project Iris.xcodeproj -scheme Iris -configuration Debug build

# Run tests
xcodebuild test -scheme Iris -destination 'platform=macOS'

# CLI control (app must be running)
swift scripts/iris-ctl.swift status        # Dump app status to /tmp/iris-status.json
swift scripts/iris-ctl.swift reinstall     # Clean reinstall all extensions
swift scripts/iris-ctl.swift sendCA        # Resend CA to proxy extension
swift scripts/iris-ctl.swift startProxy    # Enable transparent proxy
```

The app requires System Extension approval in System Settings > Privacy & Security.

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                          IrisMainApp                                  │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐ ┌──────┐ ┌───────┐ │
│  │Process  │ │Security │ │DiskUsage│ │ WiFi   │ │ DNS  │ │Proxy  │ │
│  │Store    │ │Store    │ │Store    │ │ Store  │ │Store │ │Store  │ │
│  └───┬─────┘ └───┬─────┘ └─────────┘ └────────┘ └──┬───┘ └──┬────┘ │
│      │XPC        │XPC                               │XPC     │XPC    │
└──────┼───────────┼──────────────────────────────────┼────────┼───────┘
       ▼           ▼                                  ▼        ▼
┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐
│IrisEndpoint│ │IrisNetwork │ │IrisDNS     │ │IrisProxy   │
│Extension   │ │Extension   │ │Extension   │ │Extension   │
│(ES)        │ │(NEFilter)  │ │(NEDNSProxy)│ │(NEAppProxy)│
└────────────┘ └────────────┘ └────────────┘ └────────────┘
```
Also: CertificateStore (no XPC), SatelliteStore (no XPC), SecurityAssessmentStore (no XPC)

## Package Responsibilities

| Package | Purpose | Key Files |
|---------|---------|-----------|
| IrisShared | Protocols, errors, ExtensionManager, ExtensionTypes | `ExtensionManager.swift`, `*XPCProtocol.swift`, `ExtensionTypes.swift` |
| IrisProcess | Process monitoring via ES | `ProcessStore.swift`, `ProcessInfo.swift` |
| IrisNetwork | Network monitoring + firewall rules | `SecurityStore.swift`, `SecurityRule.swift` |
| IrisDisk | Disk usage scanning | `DiskUsageStore.swift`, `DiskScanner.swift` |
| IrisSatellite | 3D satellite visualization | `SatelliteStore.swift`, `SatelliteView.swift` |
| IrisCertificates | CA/leaf cert generation, keychain | `CertificateGenerator.swift`, `CertificateStore.swift` |
| IrisWiFi | WiFi monitoring via CoreWLAN | `WiFiStore.swift`, `WiFiMonitorView.swift` |
| IrisProxy | Proxy data models (shared types) | `ProxyStore.swift`, `ProxyMonitorView.swift` |
| IrisDNS | DNS monitoring, DoH client, DNS models | `DNSStore.swift`, `DNSMonitorView.swift`, `DoHClient.swift` |
| IrisSecurity | 49 scanners, detection engine, 9 rule modules, threat intel, security views | `SecurityAssessor.swift`, `DetectionEngine.swift`, `RuleLoader.swift` |
| IrisApp | Main UI, home screen, settings, CLI handler | `HomeView.swift`, `SettingsView.swift`, `CLICommandHandler.swift` |

## Key Entry Points

| Feature | Start Here |
|---------|------------|
| Extension installation | `ExtensionManager.swift` (manages .network, .endpoint, .proxy, .dns) |
| Process monitor | `ProcessStore.swift` → `ProcessListView.swift` (Monitor/History tabs) |
| Network connections | `SecurityStore.swift` → `NetworkMonitorView.swift` |
| DNS monitoring | DNS is a tab in Network Monitor → `DNSTabView.swift` |
| HTTP inspection | `IPDetailPopover.swift` → `HTTPRawDetailView` |
| HTTP proxy flows | `ProxyStore.swift` → `ProxyMonitorView.swift` |
| Disk usage | `DiskUsageStore.swift` → `DiskUsageView.swift` |
| WiFi monitoring | `WiFiStore.swift` → `WiFiMonitorView.swift` |
| TLS interception | `TLSInterceptor.swift` (in IrisProxyExtension) |
| Proxy flow handling | `AppProxyProvider.swift` → `FlowHandler` actor |
| Security scans | `SecurityHubView.swift` → `ThreatScanView.swift` |
| Main navigation | `HomeView.swift` (circular stone menu, 8 buttons) |
| CLI remote control | `CLICommandHandler.swift` ← `scripts/iris-ctl.swift` |

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

**ExtensionManager** manages `.network`, `.endpoint`, `.proxy`, and `.dns` extension types. Each has Published state + install/uninstall/polling.

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
- Protocols defined in: `Shared/` (compiled into all 6 targets)
- Extension side: `NSXPCListener(machServiceName:)` + delegate

### Model Requirements

All models: `Identifiable, Sendable, Codable, Equatable`

### File Splitting Pattern

When a file exceeds ~250 lines, split using `FileName+Category.swift`:
- Change `private` → `internal` for properties/methods accessed cross-file
- Category name describes WHAT, not "Helpers": `+Formatting`, `+NetworkIO`, `+ProcessParsing`

## Entitlements

All entitlements files already include these NE provider types:
- `dns-proxy` - For NEDNSProxyProvider (IrisDNSExtension - working)
- `dns-settings` - For NEDNSSettingsManager
- `app-proxy-provider` - For NEAppProxyProvider (IrisProxyExtension - working)
- `content-filter-provider` - For NEFilterDataProvider (IrisNetworkExtension - working)
- `packet-tunnel-provider` - For NEPacketTunnelProvider (not used — kept for future)

## Known Issues / Gotchas

1. **Extension caching**: Old extensions can linger. Use `ExtensionManager.shared.cleanReinstallExtensions()` for Code 9 errors.
2. **App Groups must match**: `NEMachServiceName` in Info.plist must be prefixed with App Group from entitlements.
3. **Full Disk Access check**: Use `try? Data(contentsOf:)`, not `FileManager.isReadableFile()`.
4. **XPC service names**: Must match between Info.plist and code exactly.
5. **system_profiler SPAirPortDataType -json**: How to get MCS/NSS for WiFi (not CoreWLAN).
6. **SSLCreateContext is DEPRECATED**: TLS 1.2 max. Currently used for client-facing MITM (acceptable for local). Plan to migrate to SwiftNIO + swift-nio-ssl.
7. **NEAppProxyTCPFlow gives raw bytes**: Can't use NWConnection TLS for client-facing side. TLSSession.swift bridges this via SSLSetIOFuncs callbacks.
8. **No Package.swift files**: Packages are Xcode-managed local packages, not standalone SPM. Configure via Xcode project.
9. **All packages compile into one module**: Cross-package `import IrisShared` fails — all packages compile into module `Iris`. Just use the types directly.
10. **NEDNSProxyManager required**: After DNS extension activates, MUST configure NEDNSProxyManager or DNS traffic won't route to extension. DNSProxyManager handles this.
11. **DNS XPC app group**: Main app entitlements MUST include `$(TeamIdentifierPrefix)com.wudan.iris.dns.xpc` for DNS XPC to work.
12. **DNS over TCP**: Uses 2-byte big-endian length prefix (RFC 1035 Section 4.2.2). Don't assume DNS is UDP-only.
13. **SWIFT_APPROACHABLE_CONCURRENCY=YES**: Crashes compiler on IrisProxyExtension — set to NO for that target.
14. **Actor-isolated in TaskGroup**: Can't capture actor-isolated properties in @Sendable closures — capture in local `let` first.
15. **`[UInt8]` has no `.baseAddress`**: Use `.withUnsafeBufferPointer { $0.baseAddress! }` instead.
16. **`import` at bottom of file**: Can crash Swift compiler — always put imports at top.
17. **`for i in array.indices` + `await`**: If array is `@Published`, another task can replace it during suspension → index out of bounds. Fix: snapshot before loop, apply after.
18. **Shared/ can't have DESIGN.md**: Xcode copies it into all extension bundles, causing duplicate output conflicts.
19. **Reinstall chain**: `pendingOperation` must stay `.reinstallAfterCleanup` until DNS (final) completes, or the chain breaks after the first extension.
20. **secd unreachable from extensions**: Extensions run as root, can't access security daemon. Use `SecKeychainCreate` (legacy file-based keychain in /tmp) for identity creation.
21. **NE config persistence**: `cleanConfiguration()` is destructive — only use for clean reinstall, not on every `enableProxy()` call. Configs persist across app restarts.
22. **OS log levels**: `.info` logs don't persist in unified log — use `.error` for diagnostics you need to read via `log show`.

## Don't Do This

- **Don't use `print()`** - Use `Logger` from os.log
- **Don't add singletons without injection** - Use `.shared` but allow init injection for testing
- **Don't put multiple views in one file** - Split into separate files
- **Don't hardcode magic numbers** - Named constants with comments
- **Don't use SSLCreateContext for new code** - It's deprecated, TLS 1.2 max
- **Don't name split files `+Helpers`** - Use descriptive names: `+Formatting`, `+NetworkIO`, `+ProcessParsing`

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
├── Shared/                     # 11 files: XPC protocols, HTTPParser, DEREncoder, CaptureSegment, AtomicFlag (compiled into all 6 targets)
├── IrisApp/                    # App entry point + CLI handler
│   ├── IrisApp.swift           # @main App struct, startup sequence (CA → proxy → sendCA)
│   └── CLICommandHandler.swift # DistributedNotificationCenter command receiver
├── IrisNetworkExtension/       # Network filter extension (NEFilterDataProvider)
├── IrisEndpointExtension/      # Endpoint security extension (ESClient)
│   ├── ESClient.swift          # ES client, 23 event types (+ProcessLifecycle, +ProcessParsing, +Seeding, +FileEvents, +SecurityEvents, +Muting, +RingBuffer)
│   └── main.swift
├── IrisProxyExtension/         # App proxy extension (~20 files, +Category split pattern)
│   ├── AppProxyProvider.swift  # Flow interception entry point
│   ├── FlowHandler.swift       # Routes to MITM, HTTP, or passthrough (+NetworkIO, +HTTPRelay, +Passthrough, +MITMRelay)
│   ├── TLSInterceptor.swift    # Per-host cert generation (+ASN1, +CertBuilder, +DERParsing)
│   ├── TLSSession.swift        # SSLCreateContext wrapper (+Handshake, +IOCallbacks, +ReadWrite)
│   ├── ProxyXPCService.swift   # XPC listener (+FlowManagement, +XPCProtocol)
│   ├── RelayState.swift        # Thread-safe shared state for relay task groups
│   └── main.swift
├── IrisDNSExtension/           # DNS proxy extension (NEDNSProxyProvider)
│   ├── DNSProxyProvider.swift  # Intercepts DNS, DoH forwarding (+FlowHandlers, +Parsing)
│   ├── ExtensionDoHClient.swift # Lightweight DoH client using IP addresses directly
│   ├── DNSExtensionXPCService.swift # XPC service for app communication
│   └── main.swift
├── scripts/
│   ├── iris-ctl.swift          # CLI controller — sends commands to running app
│   ├── iris-logs.sh            # Stream extension logs with filters
│   ├── iris-test-proxy.sh      # End-to-end MITM pipeline test
│   ├── iris-diag.sh            # System diagnostics
│   ├── session-context.sh      # SessionStart hook (git, extensions, proxy, CA)
│   ├── verify-build.sh         # Stop hook (blocks if build fails)
│   └── swift-format-hook.sh    # PostToolUse hook (auto-format + size guard)
├── Packages/
│   ├── IrisShared/             # ExtensionManager, ExtensionTypes, XPC protocols, errors
│   ├── IrisProcess/            # Process monitoring (Monitor/History tabs, tree view)
│   ├── IrisNetwork/            # Network monitor (SecurityStore, IPDetailPopover, firewall rules)
│   ├── IrisDisk/               # Disk usage
│   ├── IrisSatellite/          # 3D satellite (Metal)
│   ├── IrisCertificates/       # CA + leaf cert generation, KeychainManager
│   ├── IrisWiFi/               # WiFi monitoring (CoreWLAN + system_profiler)
│   ├── IrisProxy/              # Proxy UI (ProxyStore, ProxyMonitorView, HTTPFlowDetailView)
│   ├── IrisSecurity/           # APT detection (35 scanners, detection engine, rules, threat intel, 15+ views)
│   ├── IrisDNS/                # DNS monitoring
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

## Current Development State (2026-02-14)

All 5 targets build (including CodeSign). 11 packages, 4 system extensions, 394 Swift files / 49K lines.

**All features working:** Network filter + firewall rules, proxy MITM (with HTTP pipelining support), WiFi, disk, satellite, process monitoring, certificates, DNS, security scanning + real-time detection engine, CLI remote control. All packages and extensions in Xcode project.

**File size distribution:** 1 file >300 (shader, exempted), 21 in 251-300 (acceptable), 84 in 151-250 (sweet spot), 198 in 51-150, 47 under 50. Zero generic file names, zero dead code.

**Process Monitor:** Two-view system via Monitor/History tabs. Monitor view: HSplitView with suspicious processes (left, live 2s refresh) + parent-child tree (right, 30s snapshot). History view: chronological timeline of all processes seen this session, with live/exited status. ES extension subscribes to 23 event types (process lifecycle + file + privilege + injection + system + auth), dual ring buffer (5000 process events + 10000 security events), app fetches via `getRecentEvents()` and `getSecurityEventsSince()` XPC.

**DNS Tab:** DNS monitoring is a tab in Network Monitor (`NetworkViewMode.dns`), not a standalone view. Uses its own extension status (separate from network filter). Home screen DNS button is a stub.

**Firewall:** Process dedup by signing identity (`identityKey`), SecurityRule CRUD via XPC, rule persistence (JSON in ApplicationSupport), inline allow/block in UI, connection conversation view with timestamped CaptureSegments.

**IrisSecurity (119 files, ~14K lines):** 49 scanners covering all 12 hunt-script categories (process, network, filesystem, kernel, firmware, identity, IPC, persistence, memory, logs, hardware), real-time detection engine (DetectionEngine + SecurityEventBus + AlertStore), 9 rule modules (CredentialTheft, Persistence, C2, Evasion, Injection, Exfiltration, APT, Correlation), multi-event correlation rules, threat intel database (48 persistence labels, 35 C2 domains, 35 targeted paths, 30 masquerade processes). Evidence-based scoring (PersistenceScanner), IPSW baseline structure (baseline-25C56.json, 50KB). ProcessEnumeration shared helper. SigningVerifier with Team ID + hardened runtime. ProcessAnomaly factories (.filesystem(), .forProcess()). All 49 scanners wired via SecurityAssessor async let. Services/ is flat — scanner names are descriptive.

**CLI Toolchain:** `CLICommandHandler` in app listens for `DistributedNotificationCenter` commands. `scripts/iris-ctl.swift` sends commands and reads `/tmp/iris-status.json`. Supports: status, reinstall, startProxy, stopProxy, sendCA, checkExtensions.

**Proxy MITM:** CA generated in app → sent to extension via XPC. Per-host certs via temp file-based keychain (`SecKeychainCreate` in /tmp). Thread-safe CA access via `caLock`. `TransparentProxyManager.ensureRunning()` reconnects on app launch. `enableProxy()` only called during installation. HTTP pipeline fix: response body completeness tracking (Content-Length + chunked) before resetting for next request.

**Now working (SIP disabled):** TCCMonitor reads both user and system TCC.db via sqlite3 CLI, flags suspicious permission grants, wired to SecurityHubView. NetworkAnomalyDetector uses structured NEFilter connection data for PID-to-connection mapping, detects C2 beaconing via coefficient of variation analysis.

**Architecture is optimal:** NEFilterDataProvider + NEAppProxyProvider + NEDNSProxyProvider. NEPacketTunnelProvider was researched and rejected (see DESIGN_DECISIONS.md).

## Related Documents

- **[DESIGN_DECISIONS.md](DESIGN_DECISIONS.md)** — TLS MITM architecture, DNS architecture, Phase 3 cancellation, evidence scoring model
- **[AUDIT.md](AUDIT.md)** — All bug findings from 4 audit rounds, organized by component with OPEN/FIXED status
- **[../iris-research/THREAT_MODEL.md](../iris-research/THREAT_MODEL.md)** — 10 nation-state attack scenarios with MITRE ATT&CK mapping
- **[../iris-research/SCANNER_INVENTORY.md](../iris-research/SCANNER_INVENTORY.md)** — All 20+ scanners cataloged
- **[../iris-research/DETECTION_GAPS.md](../iris-research/DETECTION_GAPS.md)** — P0-P3 gap analysis
