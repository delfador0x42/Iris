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
┌─────────────────────────────────────────────────────────┐
│                    IrisMainApp                          │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ ProcessStore│  │SecurityStore │  │DiskUsageStore │  │
│  └──────┬──────┘  └──────┬───────┘  └───────────────┘  │
│         │XPC             │XPC                           │
└─────────┼────────────────┼──────────────────────────────┘
          ▼                ▼
┌─────────────────┐ ┌─────────────────┐
│IrisEndpoint     │ │IrisNetwork      │
│Extension        │ │Extension        │
│(ES framework)   │ │(NE framework)   │
└─────────────────┘ └─────────────────┘
```

## Package Responsibilities

| Package | Purpose | Key Files |
|---------|---------|-----------|
| IrisShared | Protocols, errors, ExtensionManager | `ExtensionManager.swift`, `*XPCProtocol.swift` |
| IrisProcess | Process monitoring via ES | `ProcessStore.swift`, `ProcessInfo.swift` |
| IrisNetwork | Network monitoring + firewall rules | `SecurityStore.swift`, `SecurityRule.swift` |
| IrisDisk | Disk usage scanning | `DiskUsageStore.swift`, `DiskScanner.swift` |
| IrisSatellite | 3D satellite visualization | `SatelliteStore.swift`, `Renderer.swift` |
| IrisApp | Main UI, home screen, settings | `HomeView.swift`, `SettingsView.swift` |

## Key Entry Points

| Feature | Start Here |
|---------|------------|
| Extension installation | `ExtensionManager.swift` |
| Process list | `ProcessStore.swift` → `ProcessListView.swift` |
| Network connections | `SecurityStore.swift` → `NetworkMonitorView.swift` |
| Disk usage | `DiskUsageStore.swift` → `DiskUsageView.swift` |
| Main navigation | `HomeView.swift` |

## Patterns to Follow

### Store Pattern (MVVM)

All stores follow this structure:

```swift
@MainActor
public final class FooStore: ObservableObject {
    // MARK: - Published State
    @Published public private(set) var items: [Item] = []
    @Published public private(set) var isLoading = false
    @Published public private(set) var errorMessage: String?

    // MARK: - Properties
    private let logger = Logger(subsystem: "com.wudan.iris", category: "FooStore")
    private var xpcConnection: NSXPCConnection?

    // MARK: - Public Methods
    public func refresh() async { ... }
    public func connect() { ... }
    public func disconnect() { ... }
}
```

### XPC Communication

- App → Extension: `NSXPCConnection` with Mach service name
- Service names: `99HGW2AR62.com.wudan.iris.{network,endpoint}.xpc`
- Data format: JSON-encoded structs sent as `[Data]` arrays
- Protocols defined in: `Packages/IrisShared/Sources/IrisShared/Protocols/`

### Model Requirements

All models should conform to: `Identifiable, Sendable, Codable, Equatable`

```swift
public struct MyModel: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    // ...
}
```

## Known Issues / Gotchas

1. **Extension caching**: Old extensions can linger after code changes. Use `ExtensionManager.shared.cleanReinstallExtensions()` to fix Code 9 errors.

2. **App Groups must match**: The `NEMachServiceName` in `IrisNetworkExtension/Info.plist` must be prefixed with an App Group from the entitlements file.

3. **Full Disk Access check**: Use actual file read (`try? Data(contentsOf:)`), not `FileManager.isReadableFile()` which gives false positives for TCC-protected files.

4. **XPC service names**: Network uses `network.xpc`, Endpoint uses `endpoint.xpc`. These must match between Info.plist and code.

## Don't Do This

- **Don't use `print()`** - Use `Logger` from os.log instead
- **Don't add singletons without injection** - Use `.shared` but also allow init injection for testing
- **Don't put multiple views in one file** - Split into separate files
- **Don't hardcode magic numbers** - Create named constants with comments

## Testing

- Framework: Swift Testing (`@Suite`, `@Test`, `#expect`)
- Mock pattern: See `Tests/IrisSatelliteTests/Mocks/MockSatelliteDataSource.swift`
- Dependency injection: `SatelliteStore(dataSource:)` accepts mock data sources

```swift
@Suite("MyTests")
struct MyTests {
    @Test func testSomething() async {
        let mock = MockDataSource()
        let store = MyStore(dataSource: mock)
        #expect(store.items.isEmpty)
    }
}
```

## Team & Bundle IDs

- Team ID: `99HGW2AR62`
- App Bundle: `com.wudan.iris`
- Network Extension: `com.wudan.iris.network.extension`
- Endpoint Extension: `com.wudan.iris.endpoint.extension`

## File Locations

```
iris/
├── IrisApp/                    # App entry point
├── IrisNetworkExtension/       # Network filter extension
├── IrisEndpointExtension/      # Endpoint security extension
├── Packages/
│   ├── IrisShared/Sources/IrisShared/
│   │   ├── Services/ExtensionManager.swift
│   │   ├── Protocols/*.swift   # XPC protocols
│   │   └── Errors/IrisError.swift
│   ├── IrisProcess/Sources/IrisProcess/
│   │   ├── State/ProcessStore.swift
│   │   └── Models/ProcessInfo.swift
│   ├── IrisNetwork/Sources/IrisNetwork/
│   │   ├── State/SecurityStore.swift
│   │   └── Models/{NetworkConnection,SecurityRule}.swift
│   ├── IrisDisk/Sources/IrisDisk/
│   └── IrisSatellite/Sources/IrisSatellite/
├── Tests/
└── Iris.xcodeproj/
```
