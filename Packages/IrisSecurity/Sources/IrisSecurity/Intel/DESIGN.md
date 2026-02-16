# Intel — Threat Intelligence Data

## What This Does
Static threat intelligence: known malware persistence patterns, C2 indicators,
and targeted file paths. Scanners query these tables to classify findings
against known threats rather than just detecting anomalies.

## Why This Design
Intelligence data changes independently from detection logic. Keeping it
separate means we can update IOCs without touching scanner code. Each file
covers one MITRE tactic category.

## Decisions Made
- Static let dictionaries, not database — fast lookup, no I/O at scan time
- No external feed integration yet — data is curated from public reports
- MalwareC2 covers macOS-specific C2 infrastructure (not generic IPs)
- ThreatIntel aggregates across categories for cross-reference

## Key Files
- MalwarePersistence.swift — known malware persistence indicators and paths
- MalwareC2.swift — C2 server patterns, domains, user-agent signatures
- TargetedPaths.swift — file paths commonly targeted by macOS malware
- ThreatIntel.swift — aggregation layer across all intel categories
