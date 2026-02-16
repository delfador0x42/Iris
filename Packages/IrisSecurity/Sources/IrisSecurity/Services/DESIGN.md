# Services — Security Scanners & Monitors

## What This Does
84 scanner files organized by MITRE ATT&CK tactic. Each scanner examines one
attack surface (persistence, credential access, evasion, etc.) and returns
[ProcessAnomaly]. Large scanners use +Category extension pattern to stay
under 100 lines per file.

## Why This Design
One scanner, one concern. Actors for thread safety. Static singletons for
shared state (SigningVerifier, LOLBinDetector). Extension splits by theme
(+Launch, +Shell, +Browser) not by size — each extension file is a coherent
scanning domain.

## Data Flow
```
SecurityAssessor.scanThreats()
  → runs all scanners concurrently (async let / TaskGroup)
  → each scanner returns [ProcessAnomaly]
  → SecurityAssessor merges + deduplicates
  → ScanSession stores results, triggers binary analysis
```

## Decisions Made
- ProcessSnapshot.capture() taken once, shared across all scanners — consistency
- LOLBin data tables in +Data.swift extension — pure data, no logic
- FileSystemBaseline hashes in parallel (8-way TaskGroup) — performance
- KextAnomalyDetector shells out to kextstat (no pure-Swift alternative)
- PersistenceScanner+Shell at 288 lines — borderline, content analysis patterns
  are inherently verbose; splitting would fragment related checks

## Key Files (by tactic)
- PersistenceScanner+*.swift — launchd, login, browser, shell, system persistence
- LOLBinDetector+*.swift — living-off-the-land binary abuse detection
- StealthScanner+*.swift — hidden artifacts, PAM, sudoers, DYLD injection
- KextAnomalyDetector+*.swift — kernel extension and driver anomalies
- FileSystemBaseline+*.swift — filesystem integrity monitoring
- BinaryAnalysisEngine.swift — orchestrates static binary analysis pipeline
