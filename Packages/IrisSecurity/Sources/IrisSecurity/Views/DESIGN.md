# Views — SwiftUI Presentation Layer

## What This Does
Renders scan results, threat dashboards, and monitoring panels. Groups
duplicate findings by (technique, processName) for clean presentation.
Uses ThemedScrollView for styled scrollbars throughout.

## Why This Design
Views only read state — no business logic, no scanning. ScanSession is the
single source of truth via @ObservedObject. Large views split by concern:
SecurityHubView has +Sidebar, +Module, +ScannerGrid extensions.

## Data Flow
```
ScanSession (@Published) → ScanResultsView → AnomalyGroup.group() → AnomalyGroupRow
ScanSession.binaryAnalyses → AnomalyGroupRow → AnalysisPanel → BinaryAnalysisSection
SecurityAssessmentStore → SecurityDashboardView → SecurityCheckRow
```

## Decisions Made
- AnomalyGroup.group() called in view body — O(n) grouping, not worth caching
- AnalysisPanel is a disclosure-style expandable — keeps scan list scannable
- SecurityHubView split into 4 files — hub is the most complex view
- ScanResultsView sections ordered by severity: correlations > critical > high > supply chain > fs > medium > low
- ThreatScanView+Rows at 191 lines — row variants are inherently verbose

## Key Files
- ScanResultsView.swift — main findings list, streams results as scanners complete
- AnalysisPanel.swift — expandable detail panel with evidence + binary analysis
- SecurityDashboardView.swift — security grade + check summary
- SecurityHubView.swift — central hub with sidebar, modules, scanner grid
- BinaryAnalysisSection.swift — risk score, signing, entropy, strings, symbols
