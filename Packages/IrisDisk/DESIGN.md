# IrisDisk — Disk Usage Analysis

## What This Does
Scans the filesystem recursively, builds a tree of directories/files sorted
by size, and displays an interactive tree view for exploring disk usage.
Supports scan cancellation, progress reporting, and persistent caching.

## Why This Design
DiskScanner is an actor (not a class) because filesystem traversal is I/O
bound and benefits from structured concurrency. The tree model (DiskNode)
is a simple recursive struct — no need for a database when the scan result
fits in memory and can be cached as JSON.

## Data Flow
```
User taps "Scan" → DiskUsageStore.startScan()
  → DiskScanner.scan(root: "/")
    → recursive walk: FileManager.contentsOfDirectory
    → calculate sizes, prune to top 20 per directory
    → emit progress callbacks (files scanned, total size, current path)
  → DiskNode tree → DiskScanState.completed
  → cache to JSON file for fast reload
  → DiskTreeView renders expandable tree
```

## Decisions Made
- **Actor-based scanner** — thread-safe without manual locking. Filesystem
  I/O is naturally async.
- **Top-N pruning** — only keep 20 largest items per directory. Prevents
  tree from being overwhelming and keeps memory bounded.
- **Ignored paths** — /System/Volumes, /private/var/vm, and other virtual
  filesystems are skipped to avoid double-counting and infinite loops.
- **JSON cache** — scan results persisted as JSON. Faster than re-scanning
  on app launch. Cache invalidated by age, not filesystem changes.
- **Cancellation** — long scans (millions of files) are cancellable via
  Swift structured concurrency Task.checkCancellation().

## Key Files
- `State/DiskUsageStore.swift` — Main store, cache management
- `Models/DiskNode.swift` — Recursive tree node (name, path, size, children)
- `Models/DiskScanState.swift` — State machine (idle/scanning/completed/error)
- `Services/DiskScanner.swift` — Actor-based filesystem scanner
- `Views/DiskUsageView.swift` — Main UI with scan controls
- `Views/DiskTreeView.swift` — Interactive tree view
- `Views/DiskSizeBar.swift` — Visual size bar with percentage
