# IrisSecurity — Evidence-Based macOS Threat Detection

## What This Does
Comprehensive macOS security scanner: 20 detection engines across persistence,
process integrity, credential theft, supply chain, stealth techniques, and more.
Every finding carries weighted evidence that accumulates into a suspicion score.
Nothing gets a pass — everything is audited and visible, from stock Apple daemons
to unsigned cron jobs running curl|bash from /tmp.

## Why This Design
**Evidence accumulation, not binary flags.** Old model: `isSuspicious: Bool`.
New model: `evidence: [Evidence]` where each piece has a weight (0.0–1.0) and
category (signing, content, location, behavior, context). Score = sum of weights,
clamped [0,1]. Weights only go UP — nothing reduces suspicion. IPSW baseline
(macOS 26.2 build 25C56) provides a context tag (`isBaselineItem`) that says
"ships with stock macOS" but does NOT affect the score. Every item is visible.

## Scoring
- 0.0 (no evidence) → low — still visible, still auditable
- 0.3–0.6 → medium
- 0.6–0.8 → high
- 0.8+ → critical

## Data Flow
```
SecurityHubView → 11 module cards → dedicated views
  ThreatScanView → 15 scanner engines (ProcessAnomaly output)
    1. ProcessSnapshot.capture() — single pass, shared across 6 PID-based scanners
    2. LOLBin, Stealth, Integrity, Credential, DYLD, DylibHijack use snapshot
    3. XPC, Network, Kext, Auth, Persistence, EventTap, TCC, SupplyChain, FS run independently
  PersistenceView → PersistenceScanner (13 locations, Evidence model)
  EventTapView → EventTapScanner (CGGetEventTapList)
  DylibHijackView → DylibHijackScanner + MachOParser
  + FileIntegrity, SupplyChain, AVMonitor, TCC, Ransomware, PackageInventory

PersistenceScanner flow:
  scanAll() → 6 parallel sub-scans → [PersistenceItem]
    each item: evidence[] accumulates → suspicionScore (computed) → severity
    BaselineService tags isBaselineItem from IPSW baseline-25C56.json
```

## Decisions Made
- **Evidence only accumulates up** — no negative weights, no passes, no suppressions
- **IPSW baseline is context-only** — extracted from real IPSW mount, not live system
- **Backward compatible** — `isSuspicious` and `suspicionReasons` derived from evidence
- **Per-scanner evidence weights** — each scanner defines domain-specific evidence factors
- **MITRE ATT&CK IDs** on every ProcessAnomaly finding

## Key Files — Infrastructure
- Services/ProcessSnapshot.swift — one-shot PID/path/parent capture, eliminates ~4000 redundant syscalls
- Services/ProcessEnumeration.swift — shared PID/path/parent helpers (deduplicated from 8 scanners)
- Models/Evidence.swift — EvidenceCategory enum, Evidence struct, score/severity helpers
- Models/PersistenceItem.swift — evidence array, isBaselineItem, computed score/severity
- Services/BaselineService.swift — loads baseline-25C56.json (418 daemons, 460 agents, 674 kexts)

## Key Files — Scanners (31 files)
- Services/PersistenceScanner.swift + 5 extensions — 13 persistence locations with evidence
- Services/LOLBinDetector.swift — 44 LOLBins, recursive ancestry (8 levels), accepts ProcessSnapshot
- Services/DyldEnvDetector.swift — DYLD_ in processes, plists, shells, accepts ProcessSnapshot
- Services/ProcessIntegrityChecker.swift — injected dylib + CS flag detection, accepts ProcessSnapshot
- Services/CredentialAccessDetector.swift — keychain/SSH/browser cred access, accepts ProcessSnapshot
- Services/DylibHijackScanner.swift — @rpath/weak hijack detection, accepts ProcessSnapshot
- Services/StealthScanner.swift — 9 stealth techniques, accepts ProcessSnapshot
- Services/EventTapScanner.swift — CGGetEventTapList, 30+ known-benign
- Services/SigningVerifier.swift — SecStaticCode + Team ID + hardened runtime

## Key Files — Views (13 files)
- Views/SecurityHubView.swift — 11-module command center
- Views/ThreatScanView.swift — 15-engine full sweep, creates ProcessSnapshot at scan start
- Views/PersistenceView.swift — persistence enumeration with evidence scores
