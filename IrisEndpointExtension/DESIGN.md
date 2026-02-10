# IrisEndpointExtension — Process Monitor

## What This Does
System extension that monitors process execution via Apple's Endpoint Security
framework. Subscribes to EXEC/FORK/EXIT events, maintains a live process table,
and serves snapshots to the app via XPC. Catches every process that runs —
including short-lived attack tools that sysctl polling misses.

## Why This Design
Endpoint Security is the only supported API for real-time process monitoring
on macOS. It replaced the deprecated kauth/OpenBSM interfaces. ES events are
pushed by the kernel — no polling needed. We use NOTIFY events (monitoring-only,
no blocking) to avoid adding latency to process execution.

## Data Flow
```
Any process → exec/fork/exit syscall
  → macOS ES subsystem → es_new_client callback (arbitrary thread)
  → es_copy_message → serial processingQueue
  → Extract pid, path, args, signing info from es_process_t
  → Update processTable[pid] (NSLock-protected)
  → App polls XPC every 2s → getProcesses() → snapshot under lock
  → JSON decode to ProcessInfo → ProcessStore → SwiftUI
```

On startup: sysctl KERN_PROC seeds the table with existing processes.

## Decisions Made
- **EXEC+FORK+EXIT only** — File events (OPEN/WRITE/RENAME) generate thousands
  per second. Process monitoring doesn't need them. Add later for file integrity.
- **es_copy_message + serial queue** — ES callback must return fast. Copy message,
  dispatch to our queue, free after processing. No blocking in callback.
- **es_mute_process(self)** — Prevents feedback loops from our own monitoring.
- **NSLock, not actor** — ES callback is C function pointer, can't use actors.
  Serial processingQueue + NSLock on shared dictionary is the correct pattern.
- **Sysctl seed** — ES only fires for new activity. Without seeding, existing
  processes are invisible until they re-exec or fork.
- **ESProcessInfo matches ProcessInfo shape** — Same Codable keys so app-side
  JSONDecoder works without model bridging.

## Key Files
- `ESClient.swift` — ES client, event handler, process table, sysctl seeding
- `ESXPCService.swift` — Mach XPC listener, EndpointXPCProtocol conformance
- `main.swift` — Extension entry point (creates ESClient, calls start)
