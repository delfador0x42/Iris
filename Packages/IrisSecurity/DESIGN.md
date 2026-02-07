# IrisSecurity — 18 Detection Engines, 51 Files, 8095 Lines

## What This Does
Comprehensive macOS threat detection: process integrity verification,
filesystem baseline diffing (IPSW-style), credential theft detection,
kernel extension auditing, authorization DB monitoring, DYLD injection
scanning, supply chain integrity, LOLBin abuse, stealth persistence,
event tap/keylogger detection, dylib hijack scanning, ransomware
detection, beaconing analysis, XPC auditing, CIS-Benchmark assessment.

## Why This Design
Think like the attacker. Every detection maps to real APT TTPs.
MITRE ATT&CK IDs on every finding. Actors for thread safety.
SecurityHubView as Tron-style command center entry point.

## Data Flow
```
SecurityHubView → 6 module cards → dedicated views
ThreatScanView → runs 11 scanners sequentially:
  LOLBinDetector → proc_listpids + KERN_PROCARGS2
  StealthScanner → filesystem + xattr + sysctl
  XPCServiceAuditor → directory walk + SecStaticCode
  NetworkAnomalyDetector → netstat + interval analysis
  ProcessIntegrityChecker → proc_regionfilename + CS flags
  CredentialAccessDetector → proc_pidfdinfo + file perms
  KextAnomalyDetector → kextstat + disk scan + boot-args
  AuthorizationDBMonitor → security authorizationdb + plugins
  DyldEnvDetector → KERN_PROCARGS2 env + plists + shells
  SupplyChainAuditor → brew/npm/pip/xcode audit
  FileSystemBaseline → SHA-256 hash + diff
```

## Key Files — Advanced Detection
- Services/ProcessIntegrityChecker.swift — injected dylibs, CS_DEBUGGED
- Services/FileSystemBaseline.swift — IPSW-style SHA-256 baseline+diff
- Services/CredentialAccessDetector.swift — Keychain, SSH, cloud creds
- Services/KextAnomalyDetector.swift — rootkit patterns, IOKit hooks
- Services/AuthorizationDBMonitor.swift — right weakening, auth plugins
- Services/DyldEnvDetector.swift — DYLD_ in procs, plists, shells
- Services/SupplyChainAuditor.swift — brew/npm/pip/xcode tampering

## Key Files — APT Detection
- Services/LOLBinDetector.swift — 40+ LOLBins, lineage, MITRE IDs
- Services/TCCMonitor.swift — TCC.db SHA-256 baseline + diff
- Services/StealthScanner.swift — 9 stealth persistence locations
- Services/NetworkAnomalyDetector.swift — beaconing CV analysis
- Services/XPCServiceAuditor.swift — signing mismatch detection

## Key Files — Objective-See Layer
- Services/PersistenceScanner.swift + 5 extensions — 13 locations
- Services/EventTapScanner.swift — CGGetEventTapList
- Services/DylibHijackScanner.swift + MachOParser.swift
- Services/EntropyAnalyzer.swift + RansomwareDetector.swift
- Services/PersistenceMonitor.swift — BlockBlock-style

## Key Files — UI
- Views/SecurityHubView.swift — Tron command center
- Views/ThreatScanView.swift — 11-engine full sweep
- Views/FileIntegrityView.swift — baseline + diff UI
- Views/SupplyChainView.swift — package manager audit
- Views/PersistenceView.swift — persistence enumeration
- Views/EventTapView.swift — keylogger detection
- Views/DylibHijackView.swift — Mach-O hijack scan
