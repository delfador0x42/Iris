# Shared/ — Cross-Target XPC Protocols

## What This Does
Contains the canonical `@objc` XPC protocol definitions and their associated
model types. Every target (app + 4 extensions) compiles these files, giving
all processes a shared type-level contract for IPC.

## Why This Design
Extensions are separate Xcode targets that cannot import Swift packages
(packages compile as source only into the main app via
PBXFileSystemSynchronizedRootGroup). Without a shared directory, each
extension re-declared its own local `@objc protocol`, creating drift risk.
This directory is added to all 5 targets' fileSystemSynchronizedGroups in the
pbxproj, so every target compiles the same source.

## Data Flow
```
App Store → NSXPCConnection(machServiceName:) → Extension XPC Service
         ← reply closure with [Data] / [String:Any] ←
```
All complex types cross the XPC boundary as JSON-encoded `Data`. Protocols
use only ObjC-compatible types: `Data`, `String`, `Bool`, `Int`, `[String:Any]`.

## Decisions Made
- **Shared/ not a Swift Package** — packages can't be linked to system
  extension targets without SPM, which Iris doesn't use. Directory sync is
  simpler and works.
- **Models live with protocols** — `ProxyCapturedFlow`, `DNSQueryRecord` etc.
  are defined alongside their protocol because they're serialized across XPC.
  Keeping them together prevents orphaned types.
- **Convenience inits on models** — Extension-side code works with tuples and
  raw `Data`; app-side works with `Codable`. Convenience inits bridge this.

## Key Files
- `NetworkXPCProtocol.swift` — Network filter: connections, rules, status
- `EndpointXPCProtocol.swift` — Endpoint security: events, processes
- `ProxyXPCProtocol.swift` — HTTPS proxy: captured flows + request/response models
- `DNSXPCProtocol.swift` — DNS proxy: queries, server config, statistics
