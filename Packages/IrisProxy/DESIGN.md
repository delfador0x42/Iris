# IrisProxy — HTTPS Traffic Capture UI

## What This Does
Displays captured HTTP/HTTPS flows from the proxy extension. Shows request
method, URL, status code, headers, body preview, and timing. Provides
filtering by method, status code, and search text.

## Why This Design
The proxy extension does the hard work (TLS MITM, HTTP parsing). This
package is purely the presentation layer — it polls for flows via XPC,
decodes them, and renders the list. Keeping capture and display separate
means the extension can run without the UI and vice versa.

## Data Flow
```
ProxyStore ←XPC(poll)← Proxy Extension (captured flows)
  → decode [ProxyCapturedFlow] (request + response + metadata)
  → apply filters: search query, method, status code
  → @Published flows → ProxyMonitorView
  → tap flow → HTTPFlowDetailView (request/response tabs)
```

## Decisions Made
- **Models in Shared/, not here** — ProxyCapturedFlow, ProxyCapturedRequest,
  ProxyCapturedResponse live in Shared/ProxyXPCProtocol.swift because both
  the extension (producer) and app (consumer) need them.
- **Body preview, not full body** — only first 1KB of request/response body
  crosses XPC. Full bodies would overwhelm memory for large downloads.
- **Method + status badges** — colored badges (GET=blue, POST=green,
  200=green, 4xx=orange, 5xx=red) for at-a-glance triage.
- **Interception toggle** — user can disable MITM without uninstalling the
  extension. Flows still route through proxy but aren't decrypted.

## Key Files
- `State/ProxyStore.swift` — Main store, XPC connection, published state
- `State/ProxyStore+XPC.swift` — XPC communication
- `State/ProxyStore+Filtering.swift` — Search and filter logic
- `Views/ProxyMonitorView.swift` — Main flow list with toolbar
- `Views/HTTPFlowDetailView.swift` — Request/response detail tabs
- `Views/FlowRowView.swift` — Individual flow row
- `Components/MethodBadge.swift` — HTTP method label
- `Components/StatusBadge.swift` — Status code label
