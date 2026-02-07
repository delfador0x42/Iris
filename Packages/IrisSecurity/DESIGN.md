# IrisSecurity — Threat Detection, Persistence Analysis, System Integrity

## What This Does
Comprehensive macOS security toolkit implementing 12 detection engines:
CIS-Benchmark config assessment, persistence enumeration (13 location types),
event tap/keylogger detection, mic/camera monitoring, dylib hijack scanning,
entropy-based ransomware detection, LOLBin abuse detection, TCC.db integrity
monitoring, stealth persistence scanning (emond, PAM, sudoers, SSH, SUID,
hidden agents, at jobs, DYLD injection), network anomaly/beaconing detection,
and XPC service auditing.

## Why This Design
Think like the attacker. Nation-state APTs don't drop obvious malware — they
use your system tools against you (osascript, curl, sqlite3), persist in places
nobody checks (emond, PAM modules, Authorization plugins), and communicate via
patterns that look normal (HTTPS beaconing, DNS tunneling). Every scanner is
an actor — thread-safe, parallel, no shared state. Detection uses MITRE ATT&CK
technique IDs for classification.

## Data Flow
```
ThreatScanView → runs all scanners in sequence:
  LOLBinDetector → proc_listpids + KERN_PROCARGS2 → [ProcessAnomaly]
  StealthScanner → filesystem + xattr + sysctl → [ProcessAnomaly]
  XPCServiceAuditor → directory walk + SecStaticCode → [ProcessAnomaly]
  NetworkAnomalyDetector → netstat + interval analysis → [NetworkAnomaly]
  TCCMonitor → sqlite3 TCC.db + SHA256 baseline → [TCCEntry/TCCChange]
  PersistenceScanner → 13 location types → [PersistenceItem]
  EventTapScanner → CGGetEventTapList → [EventTapInfo]
  DylibHijackScanner → MachOParser → [DylibHijack]
  AVMonitor → CoreAudio property listeners → [AVDeviceEvent]
  EntropyAnalyzer/RansomwareDetector → Shannon/chi²/π → [RansomwareAlert]
  PersistenceMonitor → regex + snapshot diff → [PersistenceChange]
```

## Decisions Made
- MITRE ATT&CK mapping: every detection carries a technique ID
- LOLBin detector: parent→child lineage analysis catches lateral movement
- TCC monitor: SHA256 baseline + diff catches silent permission grants
- Stealth scanner: covers 9 persistence locations other tools ignore
- Beaconing: coefficient of variation on connection intervals (CV < 0.3)
- Process env scanning: KERN_PROCARGS2 past argc for DYLD_INSERT_LIBRARIES

## Key Files — APT Detection Layer
- Services/LOLBinDetector.swift — 40+ LOLBins, lineage analysis, arg inspection
- Services/TCCMonitor.swift — TCC.db hashing, entry diffing, permission auditing
- Services/StealthScanner.swift — emond, PAM, sudoers, SSH, SUID, hidden agents
- Services/NetworkAnomalyDetector.swift — beaconing, raw IP, suspicious ports
- Services/XPCServiceAuditor.swift — signing mismatch, Mach service audit
- Models/ProcessAnomaly.swift — finding with MITRE ID + severity
- Models/TCCEntry.swift — TCC permission with suspicion analysis
- Views/ThreatScanView.swift — unified threat scan UI

## Key Files — Objective-See Layer
- Services/PersistenceScanner.swift + 4 extensions — 13 persistence types
- Services/EventTapScanner.swift — CGGetEventTapList keylogger detection
- Services/AVMonitor.swift — CoreAudio mic/camera monitoring
- Services/DylibHijackScanner.swift + MachOParser.swift — Mach-O analysis
- Services/EntropyAnalyzer.swift + RansomwareDetector.swift — ransomware
- Services/PersistenceMonitor.swift — BlockBlock-style change detection
- Services/SigningVerifier.swift — shared SecStaticCode verification
