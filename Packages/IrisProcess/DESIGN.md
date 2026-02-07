# IrisProcess — Process Monitoring, Resources & Suspicion Detection

## What This Does
Displays running processes with CPU/memory metrics, code signing verification,
command-line arguments, and suspicion detection. Supports flat list and
hierarchical tree views. Each process shows real-time resource usage.

## Why This Design
ES extension provides authoritative process data. Resource collection uses
proc_pidinfo(PROC_PIDTASKINFO) for CPU/memory and PROC_PIDLISTFDS for open
files. CPU percentage uses delta between samples (Mach time converted to ns).
Arguments parsed from sysctl(KERN_PROCARGS2). Suspicion analysis runs
app-side — advisory, not blocking.

## Data Flow
```
ProcessStore ←XPC(2s poll)← Endpoint Extension (process list)
  → decode [ProcessInfo]
  → getProcessArguments(pid:) via KERN_PROCARGS2
  → enrichWithResources() via ProcessResourceCollector actor
    → proc_pidinfo(PROC_PIDTASKINFO) per process
    → delta CPU% from previous sample
  → analyze: signing, path, CPU, binary existence, spawn time
  → apply user filters (search, suspicious-only, sort by CPU/mem)
  → @Published processes → ProcessListView | ProcessTreeView
```

## Decisions Made
- **Actor for resource collector** — tracks CPU time deltas safely across
  async calls. Shared singleton prunes stale PIDs each refresh.
- **9 suspicion heuristics** — unsigned, ad-hoc, suspicious path, hidden name,
  not Apple-signed, no man page, high CPU (>80%), deleted binary, recently spawned
- **Tree view via OutlineGroup** — builds tree from ppid relationships. Roots
  are processes whose parent isn't in the list.
- **CPU/memory columns in list** — color-coded: red >80%, orange >40%, cyan normal

## Key Files
- `Models/ProcessInfo.swift` — process model with resources + suspicion
- `Models/ProcessResourceInfo.swift` — CPU, memory, threads, open files
- `Services/ProcessResourceCollector.swift` — actor using proc_pidinfo
- `State/ProcessStore.swift` — store with CPU/memory sort orders + view mode
- `State/ProcessStore+DataFetch.swift` — args parsing, resource enrichment
- `Views/ProcessListView.swift` — flat list with tree toggle
- `Views/ProcessTreeView.swift` — hierarchical view via OutlineGroup
- `Views/ProcessNetworkView.swift` — per-process connections
- `Views/ProcessDetailView.swift` — detail with resources section
