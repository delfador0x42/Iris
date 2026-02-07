# IrisProcess — Process Monitoring & Suspicion Detection

## What This Does
Displays the running process list from the Endpoint Security extension and
flags suspicious processes based on code signing, execution path, and other
heuristics. Provides filtering, sorting, and detailed process inspection.

## Why This Design
The ES extension (when active) provides authoritative process data with
audit tokens. The suspicion analysis runs app-side because it's advisory —
it doesn't block execution, just highlights anomalies for the user. This
keeps the extension simple (just forward events) and the analysis updatable
without re-deploying the extension.

## Data Flow
```
ProcessStore ←XPC(2s poll)← Endpoint Extension (process list)
  → decode [ProcessInfo]
  → analyze each: signing status, path, visibility
  → flag suspicious + assign severity (low/medium/high)
  → apply user filters (search text, suspicious-only)
  → @Published processes → ProcessListView
```

## Decisions Made
- **2-second polling** — process list changes less frequently than network
  connections. Slower poll reduces CPU.
- **Suspicion heuristics, not rules** — unsigned binary in /tmp is
  suspicious. Unsigned binary in /Applications might be fine. Heuristics
  with severity levels give the user context without false-positive blocks.
- **SuspicionReason enum** — each reason carries severity. UI can sort by
  aggregate risk. Reasons: unsigned, ad-hoc signed, suspicious path,
  hidden name, not Apple-signed, no man page.

## Key Files
- `State/ProcessStore.swift` — Main store, filtering, sorting
- `State/ProcessStore+DataFetch.swift` — XPC polling, suspicion analysis
- `Models/ProcessInfo.swift` — Process model with suspicion fields
- `Views/ProcessListView.swift` — Main process list UI
- `Views/ProcessDetailView.swift` — Detailed process inspection
- `Views/ProcessRow.swift` — Row with suspicion indicator
