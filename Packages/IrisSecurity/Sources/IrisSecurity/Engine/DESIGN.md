# Engine — Detection & Correlation Core

## What This Does
Orchestrates threat detection: routes ES events through rules, correlates
cross-scanner findings, manages scan sessions, and exports results. This is
the brain — scanners are the eyes, engine is the judgment.

## Why This Design
Decoupled event bus + rule engine pattern. Scanners produce ProcessAnomaly,
CorrelationEngine finds multi-stage chains, DetectionEngine matches rules
against real-time ES events. ScanSession manages one-shot batch scans.
Separation lets us add scanners/rules without touching the engine.

## Data Flow
```
ES Events → SecurityEventBus → DetectionEngine → DetectionRule matches → Alert
Batch Scan → ScanSession → SecurityAssessor → [ProcessAnomaly] → CorrelationEngine → [Correlation]
Findings → FindingAnalyzer → MITRE mapping → ScanReportExporter
```

## Decisions Made
- FindingAnalyzer+Techniques is a 289-line pure dictionary — intentionally not split
- ScannerRegistry+Entries is a 257-line registration table — same rationale
- AllowlistStore uses flat JSON file, not CoreData — simplicity, no migration burden
- CorrelationEngine is stateless (static methods) — correlations computed per-scan

## Key Files
- ScanSession.swift — batch scan orchestrator, fires binary analysis + VT on completion
- CorrelationEngine.swift — cross-scanner chain detection (exfil, rootkit, malware install)
- DetectionEngine.swift — real-time ES event → rule matching
- SecurityEventBus.swift — pub/sub for ES events across the app
- FindingAnalyzer.swift — MITRE ATT&CK technique classification
