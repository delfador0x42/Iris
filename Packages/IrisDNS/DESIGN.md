# IrisDNS — DNS Query Monitoring UI

## What This Does
Displays captured DNS queries from the DNS proxy extension. Shows domain,
record type, response code, answers, latency, and blocked status. Provides
DoH server selection and query filtering.

## Why This Design
Like IrisProxy, this is the presentation layer for DNS data captured by the
extension. It also contains the DNS message parser and DoH client used
app-side for testing and display — the extension has its own copy
(ExtensionDoHClient) because extensions can't import packages.

## Data Flow
```
DNSStore ←XPC(1s poll)← DNS Extension (query records)
  → decode [DNSQueryRecord]
  → compute stats: total, avg latency, success rate
  → apply filters: type, blocked, search text
  → @Published queries → DNSMonitorView
  → user selects server → XPC → extension switches DoH endpoint
```

## Decisions Made
- **DNSQueryRecord in Shared/** — model lives with protocol because both
  extension and app need it for serialization.
- **Parser duplicated** — DNSMessageParser exists here (for app-side display)
  and ExtensionDoHClient in the extension (for forwarding). Can't share code
  across package/extension boundary without Shared/.
- **Server picker** — Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9
  (9.9.9.9), etc. User chooses, store sends via XPC, extension switches.
- **Statistics computed app-side** — extension tracks total count; app
  computes latency distribution and success rate from the query array.

## Key Files
- `State/DNSStore.swift` — Main store, XPC connection, statistics
- `State/DNSStore+XPC.swift` — XPC communication
- `State/DNSStore+Filtering.swift` — Search and filter logic
- `Services/DoHClient.swift` — DNS-over-HTTPS client (app-side)
- `Services/DNSMessageParser.swift` — DNS wire format parser
- `Views/DNSMonitorView.swift` — Main query list with stats
- `Views/DNSQueryDetailView.swift` — Query detail (answers, TTL)
- `Views/DoHServerPickerView.swift` — Server selection dropdown
