# Architecture

This document traces the complete data flow through Iris — from kernel events to the UI. It covers every system extension, every XPC protocol, the threading model, memory management strategy, and the extension lifecycle.

---

## System Overview

Iris is five cooperating processes:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            Iris.app                                     │
│                                                                         │
│  ┌─────────────────────────────────────┐  ┌──────────────────────────┐  │
│  │          UI Layer (SwiftUI)          │  │    Batch Detection       │  │
│  │                                     │  │                          │  │
│  │  ProcessStore    NetworkStore        │  │  SecurityAssessor        │  │
│  │  ProxyStore      DNSStore           │  │  57 Scanners             │  │
│  │  SecurityStore   ScanSession        │  │  CorrelationEngine       │  │
│  │                                     │  │  FusionEngine            │  │
│  │  (all @MainActor ObservableObject)  │  │                          │  │
│  └──────────────┬──────────────────────┘  └────────────┬─────────────┘  │
│                 │                                      │                │
│                 │ XPC (Mach services)                  │ in-process     │
│                 │                                      │                │
│  ┌──────────────┼──────────────────────────────────────┼──────────────┐ │
│  │              │     SecurityEventBus                 │              │ │
│  │              │     (polls extensions, feeds          │              │ │
│  │              │      DetectionEngine + AlertStore)    │              │ │
│  └──────────────┼──────────────────────────────────────┼──────────────┘ │
└─────────────────┼──────────────────────────────────────┼────────────────┘
                  │                                      │
    ┌─────────────┼──────────┬───────────────┐           │
    │             │          │               │           │
    ▼             ▼          ▼               ▼           │
┌────────┐ ┌──────────┐ ┌────────┐   ┌──────────┐      │
│Endpoint│ │  Proxy   │ │  DNS   │   │ Scanners │◄─────┘
│Security│ │Extension │ │Extensn.│   │ read OS  │
│  Ext.  │ │          │ │        │   │ state    │
│        │ │          │ │        │   │ directly │
└────────┘ └──────────┘ └────────┘   └──────────┘
 (ES API)   (NE API)    (NE API)     (proc_pidinfo,
                                      mach_vm_region,
                                      sysctl, etc.)
```

The three system extensions (Endpoint Security, Proxy, DNS) run as separate processes managed by `sysextd`. The batch scanner system runs inside the app process — it reads OS state directly via Mach APIs, `proc_pidinfo`, `sysctl`, filesystem inspection, and SQLite.

---

## Endpoint Security Extension

### Purpose

Subscribes to macOS Endpoint Security framework events and provides the app with a live process table and security event history.

### Event Subscription

```
ES_EVENT_TYPE_NOTIFY_EXEC          Process execution
ES_EVENT_TYPE_NOTIFY_FORK          Process fork
ES_EVENT_TYPE_NOTIFY_EXIT          Process exit
ES_EVENT_TYPE_NOTIFY_SIGNAL        Signal delivery
ES_EVENT_TYPE_NOTIFY_OPEN          File open
ES_EVENT_TYPE_NOTIFY_WRITE         File write (used by ransomware detector)
ES_EVENT_TYPE_NOTIFY_UNLINK        File deletion
ES_EVENT_TYPE_NOTIFY_RENAME        File rename (mass rename = ransomware)
ES_EVENT_TYPE_NOTIFY_SETEXTATTR    Extended attribute modification
ES_EVENT_TYPE_NOTIFY_SETUID        setuid privilege change
ES_EVENT_TYPE_NOTIFY_SETGID        setgid privilege change
ES_EVENT_TYPE_AUTH_EXEC            Authorization: execution (policy enforcement)
ES_EVENT_TYPE_AUTH_OPEN            Authorization: file open
ES_EVENT_TYPE_NOTIFY_MMAP          Memory mapping (shellcode staging)
ES_EVENT_TYPE_NOTIFY_MPROTECT      Memory protection change (RWX)
ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE  Thread injection
ES_EVENT_TYPE_NOTIFY_GET_TASK      Task port acquisition (task_for_pid)
ES_EVENT_TYPE_NOTIFY_PTRACE        Debugger attachment
ES_EVENT_TYPE_NOTIFY_KEXTLOAD      Kernel extension loading
ES_EVENT_TYPE_NOTIFY_MOUNT         Volume mount
ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED  Code signature invalidation
ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD  Background Task Management
ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME  Process suspension
```

### Data Flow

```
Kernel Event
     │
     ▼
es_new_client() callback
     │
     ├─ es_copy_message() — deep copy the ES message (must not hold reference)
     │
     ├─ AUTH events: immediate decision on processingQueue
     │  ├─ ExecPolicy.evaluate() — check blocklists
     │  └─ es_respond_auth_result() — allow or deny
     │
     └─ Dispatch to processingQueue (serial DispatchQueue)
          │
          ├─ Parse process attributes:
          │  ├─ PID, PPID, RPID (responsible PID)
          │  ├─ Binary path, args, environment
          │  ├─ Code signing: team ID, signing ID, flags, entitlements
          │  ├─ Audit token (for XPC verification)
          │  └─ User/group IDs
          │
          ├─ Update processTable[pid] under NSLock
          │  ├─ EXEC: insert/replace entry
          │  ├─ FORK: insert child with parent reference
          │  └─ EXIT: remove entry
          │
          ├─ Process events → processEventRing (5,000 slots)
          │  └─ O(1) insert: ring[writeIndex % capacity] = event
          │     writeIndex += 1
          │
          └─ Security events → securityEventRing (10,000 slots)
             └─ Same O(1) ring buffer pattern
```

### Ring Buffer Design

```swift
// Conceptual model — actual implementation uses NSLock-protected arrays
struct RingBuffer<T> {
    var storage: [T?]        // Fixed-size array
    var writeIndex: UInt64   // Monotonically increasing
    var capacity: Int        // 5000 for process, 10000 for security

    mutating func append(_ item: T) {
        storage[Int(writeIndex % UInt64(capacity))] = item
        writeIndex += 1      // Serves as sequence number
    }

    func since(_ seq: UInt64) -> [T] {
        // Return items with sequence > seq
        // Handles wraparound correctly
    }
}
```

The ring buffer provides:
- **O(1) insertion** — no array resizing, no memory allocation on insert
- **Bounded memory** — exactly `capacity × sizeof(T)` regardless of event rate
- **Monotonic sequence numbers** — the `writeIndex` is also the sequence number for delta XPC

### Event Muting

```
ESClient+Muting.swift configures event-specific path muting via es_mute_path_events()

Muted paths (per event type):
  WRITE: /private/var/log/*, ~/.cache/*, /tmp/com.apple.*
  OPEN:  /System/Library/*, /usr/share/*
  etc.

MuteSet.swift manages the muted process set:
  - System processes by signing ID (com.apple.*)
  - Known-benign by team ID
  - Event-specific: mute WRITE for Spotlight, mute OPEN for mdworker
```

This reduces event volume by ~80% without losing security-relevant events.

### ExecPolicy

The execution policy system provides real-time binary blocking:

```
ES_EVENT_TYPE_AUTH_EXEC received
     │
     ▼
ExecPolicy.evaluate(process)
     │
     ├─ Check path blocklist
     ├─ Check team ID blocklist
     ├─ Check signing ID blocklist
     │
     ├─ If match AND enforcement enabled:
     │  └─ es_respond_auth_result(ES_AUTH_RESULT_DENY)
     │     └─ Kernel prevents execution
     │
     └─ If no match OR enforcement disabled:
        └─ es_respond_auth_result(ES_AUTH_RESULT_ALLOW)
```

**Critical initialization order:** ExecPolicy must be initialized before `es_new_client()` is called. If the ES client callback fires before ExecPolicy exists, the AUTH_EXEC handler will crash trying to evaluate against a nil policy. This is enforced by the startup sequence in `main.swift`.

### XPC Interface

```swift
@objc protocol EndpointXPCProtocol {
    func getProcesses(reply: @escaping ([Data]) -> Void)
    func getRecentEvents(limit: Int, reply: @escaping ([Data]) -> Void)
    func getSecurityEventsSince(_ seq: UInt64, reply: @escaping (UInt64, [Data]) -> Void)
    func updateBlocklists(paths: [String], teamIds: [String], signingIds: [String],
                          reply: @escaping (Bool) -> Void)
    func setEnforcementMode(_ enforce: Bool, reply: @escaping (Bool) -> Void)
}
```

The extension verifies the code signature of the connecting process via `SecCodeCheckValidity` before accepting any XPC connection.

---

## Proxy Extension

### Purpose

Intercepts all outbound network traffic. Decrypts HTTPS, parses HTTP, applies firewall rules, and stores captured flows for the app.

### Flow Lifecycle

```
Application opens TCP/UDP connection
     │
     ▼
macOS Network Extension framework
     │
     ▼
AppProxyProvider.handleNewFlow(_ flow: NEAppProxyFlow) -> Bool
     │
     ├─ Extract metadata from flow:
     │  ├─ sourceAppAuditToken → PID, signing ID, path
     │  ├─ remoteHostname, remoteEndpoint (IP + port)
     │  └─ localEndpoint
     │
     ├─ Evaluate firewall rules (SecurityRule matching)
     │  ├─ Match: processPath, domain, port
     │  └─ If block: return true (claim flow) but don't relay → connection times out
     │
     ├─ Return true (claim flow) or false (let system handle)
     │
     └─ Spawn FlowHandler task for this flow
```

### FlowHandler (Actor)

Each claimed flow gets its own `FlowHandler` actor instance. Routing is by destination port:

```
FlowHandler.handleFlow(flowId, flow, host, port)
     │
     ├─ Port 443 → handleHTTPSFlow()
     │  ├─ TLS handshake with client (SSLCreateContext, server mode)
     │  ├─ NWConnection to real server (TLS 1.3, client mode)
     │  ├─ Relay loop: decrypt from client → parse HTTP → encrypt to server
     │  ├─ Relay loop: decrypt from server → parse HTTP → encrypt to client
     │  └─ Capture ProxyCapturedFlow(.https) with parsed request/response
     │
     ├─ Port 80 → handleHTTPFlow()
     │  ├─ NWConnection to real server (no TLS)
     │  ├─ Read from NEAppProxyTCPFlow → parse HTTP → send to server
     │  ├─ Read from server → parse HTTP response → send to client
     │  └─ Capture ProxyCapturedFlow(.http)
     │
     ├─ Port 53 → handleDNSFlow()
     │  ├─ Read DNS wire format from flow
     │  ├─ DoHClient.relay() → HTTPS POST to DoH server
     │  ├─ Return DNS response to flow
     │  └─ Record DNSQueryRecord
     │
     └─ Other → relayPassthrough() or relayUDP()
        ├─ NWConnection to real server
        ├─ Bidirectional byte relay with counting
        └─ Capture ProxyCapturedFlow(.tcp or .udp) — metadata only, no HTTP parsing
```

### TLS MITM Implementation

```
Client (e.g., Safari)                FlowHandler                    Real Server
         │                               │                               │
         │  raw bytes via                 │                               │
         │  NEAppProxyTCPFlow             │                               │
         │                               │                               │
         │ ─── TLS ClientHello ─────────► │                               │
         │                               │                               │
         │                    TLSSession (SSLCreateContext, server mode)   │
         │                    SSLSetIOFuncs → read/write NEAppProxyTCPFlow │
         │                    SSLSetCertificate(per-host leaf cert)        │
         │                               │                               │
         │ ◄── TLS ServerHello ───────── │                               │
         │     (Iris cert for this host)  │                               │
         │                               │                               │
         │ === TLS 1.2 Established ===== │                               │
         │                               │                               │
         │                               │ ── NWConnection(.tls) ──────► │
         │                               │ ◄─ TLS 1.3 Established ───── │
         │                               │                               │
         │  Decrypted HTTP Request        │                               │
         │ ─────────────────────────────► │                               │
         │                               │  RustHTTPParser.parseRequest() │
         │                               │  → ProxyCapturedRequest        │
         │                               │                               │
         │                               │ ── HTTP Request ────────────► │
         │                               │ ◄── HTTP Response ─────────── │
         │                               │                               │
         │                               │  RustHTTPParser.parseResponse()│
         │                               │  → ProxyCapturedResponse       │
         │                               │                               │
         │  ◄──── HTTP Response ──────── │                               │
         │  (re-encrypted via TLSSession) │                               │
```

**SSLSetIOFuncs callbacks:**
- `tlsReadFunc`: Called by SecureTransport when it needs plaintext bytes. Reads from `NEAppProxyTCPFlow.readData()`. Uses `CheckedContinuation` to bridge async flow reads to sync SSL callbacks.
- `tlsWriteFunc`: Called by SecureTransport when it has ciphertext bytes to send. Writes to `NEAppProxyTCPFlow.write()`.

**Buffer management:**
- `readBufferLock` protects the decrypted data buffer (SSLRead fills it, relay loop drains it)
- `waiterLock` protects async continuation waiters (flow I/O is async, SSL callbacks are sync)
- `sslQueue` serializes all SSLRead/SSLWrite operations

### Flow Storage

```swift
// In ProxyXPCService
var capturedFlows: [ProxyCapturedFlow] = []     // max 10,000
var capturedDNSQueries: [DNSQueryRecord] = []   // max 10,000
var connections: [UUID: ConnectionTracker] = [:] // active connections

// Eviction strategy
func addFlow(_ flow: ProxyCapturedFlow) {
    capturedFlows.append(flow)
    if capturedFlows.count > maxFlows {
        capturedFlows.removeFirst(1000)  // Batch eviction to amortize O(n) shift
    }
}
```

Memory budget: 30 MB maximum for buffered capture data. When exceeded, oldest flows are evicted.

### XPC Interface

```swift
@objc protocol ProxyXPCProtocol {
    // Delta flow retrieval
    func getFlowsSince(_ sinceSeq: UInt64, reply: @escaping (UInt64, [Data]) -> Void)

    // DNS queries (delta)
    func getDNSQueriesSince(_ sinceSeq: UInt64, limit: Int,
                            reply: @escaping (UInt64, [Data]) -> Void)

    // TLS MITM control
    func setInterceptionEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)
    func setCA(certData: Data, keyData: Data, reply: @escaping (Bool) -> Void)

    // Firewall rules
    func addRule(_ ruleData: Data, reply: @escaping (Bool) -> Void)
    func updateRule(_ ruleData: Data, reply: @escaping (Bool) -> Void)
    func removeRule(_ ruleId: String, reply: @escaping (Bool) -> Void)
    func toggleRule(_ ruleId: String, reply: @escaping (Bool) -> Void)

    // Active connections
    func getConnections(reply: @escaping ([Data]) -> Void)

    // Raw capture data
    func getConnectionRawData(_ connectionId: String,
                              reply: @escaping (Data?, Data?) -> Void)
    func getConnectionConversation(_ connectionId: String,
                                   reply: @escaping (Data?) -> Void)
}
```

---

## DNS Extension

### Purpose

Intercepts all system DNS resolution and resolves queries via DNS-over-HTTPS.

### Data Flow

```
Application calls getaddrinfo() / nw_resolver
     │
     ▼
macOS DNS subsystem routes to NEDNSProxyProvider
     │
     ▼
DNSProxyProvider.handleNewFlow(_ flow: NEAppProxyUDPFlow)
     │
     ├─ Read DNS wire format datagram
     │  ├─ UDP: single datagram
     │  └─ TCP: 2-byte big-endian length prefix (RFC 1035 §4.2.2) + message
     │
     ├─ Parse DNS header: ID, flags, question count
     ├─ Extract: query domain, query type (A/AAAA/CNAME/MX/TXT/etc.)
     │
     ├─ Forward to DoH upstream:
     │  ├─ POST https://1.1.1.1/dns-query (Cloudflare, default)
     │  │   Content-Type: application/dns-message
     │  │   Body: original DNS wire format bytes
     │  │
     │  ├─ Or: Google (8.8.8.8), Quad9 (9.9.9.9) — configurable
     │  └─ Bootstrap: uses IP addresses directly (no DNS lookup for resolver)
     │
     ├─ Parse DoH response → DNS wire format
     ├─ Record DNSQueryRecord:
     │  ├─ domain, queryType, responseCode
     │  ├─ answers (array of resolved records)
     │  ├─ TTL, latencyMs
     │  └─ processName (from audit token)
     │
     └─ Return DNS response to application
```

### XPC Interface

```swift
@objc protocol DNSXPCProtocol {
    func getDNSQueriesSince(_ sinceSeq: UInt64, limit: Int,
                            reply: @escaping (UInt64, [Data]) -> Void)
    func clearDNSQueries(reply: @escaping (Bool) -> Void)
    func setDNSEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)
    func setDNSServer(_ serverName: String, reply: @escaping (Bool) -> Void)
    func getDNSStats(reply: @escaping ([String: Any]) -> Void)
}
```

---

## SecurityEventBus

The SecurityEventBus bridges extension telemetry into the in-app detection engine:

```
SecurityEventBus (runs on background thread)
     │
     ├─ Timer fires every 1 second
     │
     ├─ Poll IrisEndpointExtension via XPC:
     │  └─ getSecurityEventsSince(lastSeq) → [ESEvent]
     │     └─ Decode each: event type, PID, path, args, signing info
     │
     ├─ Poll IrisProxyExtension via XPC:
     │  └─ getFlowsSince(lastSeq) → [ProxyCapturedFlow]
     │     └─ Generate SecurityEvent(.network) for each connection
     │
     ├─ Poll IrisDNSExtension via XPC:
     │  └─ getDNSQueriesSince(lastSeq) → [DNSQueryRecord]
     │     └─ Generate SecurityEvent(.dns) for each query
     │
     └─ Feed all SecurityEvents to DetectionEngine
          │
          ├─ DetectionEngine.evaluate(event)
          │  ├─ Check all 79 simple rules
          │  ├─ Feed to all 15 correlation rules (temporal state)
          │  └─ On match: emit Alert → AlertStore
          │
          └─ AlertStore.add(alert)
             ├─ Dedup check: same rule + same process within 60s → skip
             ├─ Insert into ring buffer (5,000 max)
             └─ If severity ≥ high: fire system notification
```

### SecurityEvent Model

```swift
struct SecurityEvent {
    let timestamp: Date
    let source: SecurityEventSource  // .endpoint, .network, .dns, .proxy
    let eventType: String            // "exec", "file_write", "connection", etc.
    let pid: pid_t
    let processName: String
    let processPath: String
    let signingID: String
    let teamID: String
    let fields: [String: String]     // Event-specific data
}
```

The `fields` dictionary carries event-specific data: file paths for file events, remote addresses for network events, DNS domains for DNS events. Detection rules match against these fields.

---

## Thread Safety Model

### Extension Threads

**Endpoint Security Extension:**
- ES callback thread (kernel-managed, must return quickly)
- `processingQueue` (serial DispatchQueue) — all event processing
- `NSLock` protects `processTable` dictionary
- Separate `NSLock` for each ring buffer

**Proxy Extension:**
- `FlowHandler` is an actor — one per flow, Swift concurrency isolates state
- `TLSSession` uses three explicit locks:
  - `readBufferLock` — protects decrypted data buffer
  - `waiterLock` — protects async continuation registration
  - `sslQueue` — serializes SSLRead/SSLWrite calls
- `ProxyXPCService` uses `NSLock` for flow/DNS/connection storage
- `RelayState` uses `NSLock` for request/response buffer access

**DNS Extension:**
- Stateless per-flow processing (each DNS query is independent)
- DoH client uses URLSession (thread-safe by design)

### App Threads

- All `Store` classes (`ProcessStore`, `SecurityStore`, `ProxyStore`, `DNSStore`) are `@MainActor` — UI updates happen on the main thread
- XPC reply closures dispatch to main actor
- `SecurityEventBus` runs its timer on a background thread
- `DetectionEngine` is a Swift actor (serializes rule evaluation)
- `SecurityAssessor` runs scanners with `TaskGroup` (structured concurrency)
- Scanner `shared` singletons are actors or use `NSLock` internally

---

## Extension Lifecycle

### Installation

```
User taps "Enable" in Settings
     │
     ▼
ExtensionManager.install(.endpoint) / .proxy / .dns
     │
     ├─ OSSystemExtensionRequest.activationRequest(
     │      forExtensionWithIdentifier: bundleID)
     ├─ Submit to OSSystemExtensionManager
     │
     ▼
macOS prompts user to approve (System Preferences → Privacy & Security)
     │
     ▼
Extension activates as a system extension
     │
     ├─ Endpoint: main.swift → ESClient.start() → es_new_client()
     ├─ Proxy: main.swift → AppProxyProvider → wait for startProxy()
     └─ DNS: main.swift → DNSProxyProvider → wait for startProxy()
```

### Network Extension Activation

After the system extension is installed, network extensions require a second step:

```
ExtensionManager.install(.proxy)
     │
     ├─ Install system extension (above)
     │
     └─ TransparentProxyManager.enable()
        ├─ NETransparentProxyManager.loadAllFromPreferences()
        ├─ Create NETransparentProxyProviderProtocol configuration
        ├─ Set appRules (match all TCP/UDP)
        └─ manager.saveToPreferences()
           └─ macOS starts routing traffic through the proxy

ExtensionManager.install(.dns)
     │
     └─ DNSProxyManager.enableDNSProxy()
        ├─ NEDNSProxyManager.loadFromPreferences()
        ├─ Set providerBundleIdentifier
        ├─ Set serverAddress = "1.1.1.1" (required by API)
        └─ manager.saveToPreferences()
           └─ macOS starts routing DNS through the proxy
```

**Critical:** Without the NEManager configuration step, the system extension runs but receives no traffic. The extension install and manager configuration are two separate operations.

### Status Monitoring

```
ExtensionManager polls extension status on a 5-second timer:

For each extension type:
  ├─ Check OSSystemExtensionManager for installed state
  ├─ Check NETransparentProxyManager / NEDNSProxyManager for enabled state
  ├─ Attempt XPC connection to verify extension is responsive
  └─ Update published status: .notInstalled, .installed, .running, .error
```

---

## Network Enrichment (App-Side)

Network connection enrichment happens in the app process, not in extensions. This keeps API keys out of the extension sandbox:

```
SecurityStore receives raw connections via XPC
     │
     ▼
Background enrichment tasks (parallel, per connection):
     │
     ├─ GeoIPService → Country, city, coordinates, ISP
     ├─ ReverseDNS → PTR record lookup
     ├─ GreyNoise → Is this IP a known scanner? Benign service?
     ├─ AbuseIPDB → Abuse confidence score, report count
     └─ InternetDB/Shodan → Open ports, CVEs, CPEs
          │
          ▼
     Merged into NetworkConnection model
          │
          ▼
     Published to UI (SecurityStore is @MainActor ObservableObject)
```

Enrichment is rate-limited and cached — the same IP is not re-queried within the cache TTL.

---

## File Organization Conventions

### 100-Line Rule

Files target ≤100 lines, with a hard maximum of 300. When a file grows beyond this:

```
FileName.swift              Core type definition, primary methods
FileName+Category.swift     Extension with focused functionality
FileName+Another.swift      Another extension
```

Categories describe **what** the extension does, not implementation details:
- `ESClient+ProcessLifecycle.swift` — EXEC/FORK/EXIT event handlers
- `FlowHandler+MITMRelay.swift` — HTTPS MITM relay logic
- `TLSInterceptor+ASN1.swift` — ASN.1 DER encoding for certificates

### Store Pattern

All UI data sources follow the same pattern:

```swift
@MainActor final class FooStore: ObservableObject {
    @Published var items: [FooItem] = []
    @Published var isLoading = false
    @Published var errorMessage: String?

    private var xpcConnection: NSXPCConnection?
    private var lastSeq: UInt64 = 0
    private var refreshTimer: Timer?

    func startPolling() {
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
            Task { @MainActor in await self.refresh() }
        }
    }

    func refresh() async {
        guard let proxy = xpcConnection?.remoteObjectProxy as? FooXPCProtocol else { return }
        proxy.getItemsSince(lastSeq) { [weak self] maxSeq, data in
            Task { @MainActor in
                self?.lastSeq = maxSeq
                let newItems = data.compactMap { try? JSONDecoder().decode(FooItem.self, from: $0) }
                self?.items.append(contentsOf: newItems)
            }
        }
    }
}
```

### Scanner Pattern

All scanners follow this structure:

```swift
final class FooScanner: Sendable {
    static let shared = FooScanner()

    func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        // 1. Enumerate relevant system state
        // 2. Check against known-good baseline
        // 3. Build ProcessAnomaly for each finding with:
        //    - PID, processName, processPath
        //    - technique (human-readable name)
        //    - description (detailed explanation)
        //    - severity (.critical / .high / .medium / .low)
        //    - mitreID (T-number)
        //    - scannerId (matches ScannerEntry.id)
        //    - enumMethod (how data was collected)
        //    - evidence ([String] of key-value pairs)
    }
}
```

Scanners are registered in `ScannerRegistry+Entries.swift` and assigned to a tier (fast/medium/slow).
