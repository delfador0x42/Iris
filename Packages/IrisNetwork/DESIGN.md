# IrisNetwork — Network Connection Monitoring & Enrichment

## What This Does
Displays live network connections from the content filter extension, enriches
IP addresses with geolocation/threat intelligence from 5+ external services,
and manages user-defined firewall rules (allow/block by process, domain, port).

## Why This Design
Raw connections (IP + port + PID) aren't useful without context. The
enrichment pipeline runs in the app (not the extension) to avoid blocking
filter verdicts and to keep API keys out of the extension sandbox. Each
enrichment service is a separate actor so failures are isolated.

## Data Flow
```
SecurityStore ←XPC(1s poll)← Network Extension (active connections)
  → decode [NetworkConnection]
  → IPEnrichmentService.enrich(ip)
    → parallel: GeoIP, GreyNoise, AbuseIPDB, ReverseDNS, InternetDB
    → merge results into connection model
  → @Published connections → NetworkMonitorView
  → user creates rule → XPC → extension applies verdict
```

## Decisions Made
- **1-second polling** — fast enough for real-time feel, slow enough to not
  overwhelm XPC. Extension stores connections; app pulls on timer.
- **Enrichment as services, not models** — services are actors with caching
  and rate limiting. Models are plain Codable structs.
- **Rules pushed to extension** — rules evaluated in-extension for latency.
  App sends rule via XPC, extension stores and applies to future flows.
- **World map visualization** — 3D globe with arcs from local to remote IP.
  Uses the same Metal rendering pattern as IrisSatellite.

## Key Files
- `State/SecurityStore.swift` — Main store, XPC connection, published state
- `State/SecurityStore+DataRefresh.swift` — 1-second polling loop
- `State/SecurityStore+Rules.swift` — Rule CRUD via XPC
- `Models/NetworkConnection.swift` — Connection with enrichment fields
- `Models/SecurityRule.swift` — Firewall rule (process/domain/port match)
- `Services/IPEnrichmentService.swift` — Aggregates all enrichment services
- `Views/NetworkMonitorView.swift` — Main connection list UI
- `Views/IPDetailPopover.swift` — Expanded IP info modal
- `Views/WorldMapView.swift` — 3D globe visualization
