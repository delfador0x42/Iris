# State — Persistent Assessment State

## What This Does
Stores and publishes the latest security assessment result. SecurityHubView
and SecurityDashboardView observe this store to display the current grade
and check results without re-scanning.

## Why This Design
Single store, @MainActor, ObservableObject — standard Iris pattern. Scan
results are ephemeral (ScanSession), but the assessment grade persists
across view navigations via this store.

## Key Files
- SecurityAssessmentStore.swift — @Published assessment, grade, checks
