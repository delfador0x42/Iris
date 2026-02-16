# Models — Value Types & Data Structures

## What This Does
All value types shared across scanners, engine, and views. Every model
conforms to Identifiable + Sendable + Codable + Equatable for actor safety,
persistence, and UI rendering.

## Why This Design
Models are the language of the system. They cross actor boundaries (scanner →
engine → view), get serialized (JSON export, baseline storage), and compared
(FindingsDiff). Full conformance set is mandatory, not optional.

## Data Flow
```
Scanner → ProcessAnomaly → CorrelationEngine → Correlation
Scanner → PersistenceItem → PersistenceView
FileSystemBaseline → FileSystemChange → FSChangeRow
BinaryAnalysisEngine → BinaryAnalysis → BinaryAnalysisSection
```

## Decisions Made
- ProcessAnomaly has factory methods (.filesystem, .forProcess) to reduce init noise
- AnomalyGroup is internal (view-layer dedup only), not public
- Evidence is a standalone struct (factor + weight + category) for scoring flexibility
- SecurityGrade computes letter grade from check results, not from raw anomalies

## Key Files
- ProcessAnomaly.swift — core finding type, used by every scanner
- PersistenceItem.swift — launchd, login items, cron, shell profile entries
- BinaryAnalysis.swift — static analysis result (signing, entropy, strings, symbols)
- Evidence.swift — weighted evidence for risk scoring
- FileSystemChange.swift — baseline diff result
