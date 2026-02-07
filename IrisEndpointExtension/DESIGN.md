# IrisEndpointExtension — Process Monitor

## What This Does
System extension that monitors process execution, file operations, and other
system events via Apple's Endpoint Security framework. Currently scaffolded —
the ES client creation is stubbed pending deployment with the approved
com.apple.developer.endpoint-security.client entitlement.

## Why This Design
Endpoint Security is the only supported API for real-time process monitoring
on macOS. It replaced the deprecated kauth/OpenBSM interfaces. It requires
a system extension (not an app extension) and Full Disk Access.

## Data Flow
```
Any process → exec/fork/open syscall
  → macOS ES subsystem → es_new_client callback
  → ESProvider: extract process info (pid, path, signing ID, ppid)
  → XPC (EndpointXPCProtocol) → ProcessStore in main app → UI
```

## Decisions Made
- **System extension, not embedded** — ES requires
  `com.apple.system-extension.install` and must run out-of-process.
- **ES entitlement approved** — Apple granted
  com.apple.developer.endpoint-security.client. Implementation pending.
- **AUTH vs NOTIFY** — will use ES_EVENT_TYPE_NOTIFY for monitoring (no
  verdict needed). AUTH events would let us block processes but add latency
  and complexity we don't need yet.
- **Separate from network extension** — ES and NE are different subsystems
  with different lifecycle requirements. Combining them would create a
  single point of failure.

## Key Files
- `ESProvider.swift` — Main provider class (ES client setup, event handling)
- `ESXPCService.swift` — Mach XPC listener, EndpointXPCProtocol conformance
- `main.swift` — Extension entry point
