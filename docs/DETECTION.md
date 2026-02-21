# Detection Engine

This document covers the complete detection pipeline: real-time rules, temporal correlation, cross-scanner correlation, kill chain fusion, campaign detection, and MITRE ATT&CK coverage.

---

## Detection Pipeline

Iris runs two independent detection paths that converge in the Security Hub UI:

```
                    ┌──────────────────────────────┐
                    │     Real-Time Detection       │
                    │                              │
ES Events ────────► │  SecurityEventBus (1s poll)  │
Network Events ──► │  → DetectionEngine (actor)    │
DNS Events ──────► │  → 79 simple rules            │
                    │  → 15 correlation rules       │
                    │  → AlertStore (5000 ring)     │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │        Security Hub UI        │
                    │                              │
                    │  Alerts + Scanner Findings    │
                    │  + Correlations + Campaigns   │
                    └──────────────┬───────────────┘
                                   ▲
                                   │
                    ┌──────────────┴───────────────┐
                    │      Batch Detection          │
                    │                              │
ProcessSnapshot ──► │  SecurityAssessor             │
Connections ──────► │  → 57 scanners (3 tiers)     │
                    │  → CorrelationEngine          │
                    │  → FusionEngine               │
                    └──────────────────────────────┘
```

---

## Real-Time Detection

### SecurityEventBus

Polls all three extensions every 1 second via XPC and normalizes events into `SecurityEvent`:

```swift
struct SecurityEvent {
    let timestamp: Date
    let source: SecurityEventSource    // .endpoint, .network, .dns, .proxy
    let eventType: String              // "exec", "file_write", "connection", etc.
    let pid: pid_t
    let processName: String
    let processPath: String
    let signingID: String
    let teamID: String
    let fields: [String: String]       // Event-specific key-value pairs
}
```

The `fields` dictionary carries event-specific data:
- File events: `path`, `targetPath` (for rename), `xattr_name`
- Network events: `remote_address`, `remote_port`, `hostname`, `protocol`
- DNS events: `domain`, `query_type`, `response_code`
- Process events: `args`, `env`, `parent_path`

### DetectionEngine

A Swift actor that evaluates every SecurityEvent against all rules:

```
DetectionEngine.evaluate(event: SecurityEvent)
     │
     ├─ For each simple rule (79 total):
     │  ├─ Check event type matches
     │  ├─ Evaluate field predicates
     │  └─ If all match: emit Alert
     │
     └─ For each correlation rule (15 total):
        ├─ Feed event into rule's temporal state
        ├─ Check if all events in sequence have been seen within window
        └─ If complete: emit Alert + clear state
```

### AlertStore

Thread-safe alert storage with deduplication:

```
AlertStore.add(alert: Alert)
     │
     ├─ Dedup check: same ruleID + same pid + within 60 seconds = skip
     │
     ├─ Insert into ring buffer (5,000 slots max)
     │  └─ O(1) insert, oldest alert evicted on overflow
     │
     └─ If severity ≥ .high:
        └─ UNUserNotificationCenter.current().add(notification)
           └─ System notification to user
```

---

## Simple Detection Rules

79 rules across 8 modules. Each rule specifies an event type and a set of field predicates. When a SecurityEvent matches the event type and all predicates evaluate true, the rule fires.

### Credential Theft Rules (7)

| Rule | Event Type | Predicate | Severity |
|------|-----------|-----------|----------|
| Chrome Login Data access | file_open | path contains "Login Data" AND processPath not Chrome | High |
| Keychain database access | file_open | path contains "keychain-db" AND process not security/keychain | Critical |
| Browser cookie theft | file_open | path contains "Cookies" AND processPath not browser | High |
| Firefox credential access | file_open | path contains "logins.json" or "key4.db" | High |
| Crypto wallet access | file_open | path matches ~/Library/Application Support/(Electrum\|Exodus\|Metamask) | High |
| SSH private key read | file_open | path matches ~/.ssh/id_* AND process not ssh/ssh-agent | High |
| Auth database read | auth_open | path is /var/db/auth.db AND process not authorizationhost | Critical |

### Persistence Rules (6)

| Rule | Event Type | Predicate | Severity |
|------|-----------|-----------|----------|
| LaunchAgent creation | file_write | path in ~/Library/LaunchAgents/*.plist | High |
| LaunchDaemon creation | file_write | path in /Library/LaunchDaemons/*.plist | Critical |
| Shell profile modification | file_write | path matches .zshrc/.bashrc/.bash_profile/.profile | Medium |
| Xcode build phase injection | file_write | path matches .xcodeproj/**/*.pbxproj | Medium |
| Crontab modification | file_write | path matches /usr/lib/cron/tabs/* or /var/at/tabs/* | High |
| BTM launch item registration | btm_launch_item_add | any | Medium |

### Command & Control Rules (19)

**Cloud C2 Domains (7):**

| Rule | Domain Pattern | MITRE |
|------|---------------|-------|
| Dropbox C2 | api.dropboxapi.com, content.dropboxapi.com | T1102.002 |
| AWS S3 C2 | *.s3.amazonaws.com, *.s3-*.amazonaws.com | T1102.002 |
| OneDrive C2 | graph.microsoft.com/*/drive | T1102.002 |
| pCloud C2 | api.pcloud.com | T1102.002 |
| Google Drive C2 | www.googleapis.com/drive | T1102.002 |
| iCloud C2 | *.icloud.com/*/ws (non-Apple process) | T1102.002 |
| Azure Blob C2 | *.blob.core.windows.net | T1102.002 |

**Dead Drop Resolvers (6):**

| Rule | Service | MITRE |
|------|---------|-------|
| Telegram API | api.telegram.org (non-Telegram process) | T1102.001 |
| Pastebin | pastebin.com/raw/ | T1102.001 |
| GitHub Gist | gist.githubusercontent.com (non-git process) | T1102.001 |
| URL Shortener | bit.ly, tinyurl.com, is.gd (non-browser) | T1102.001 |
| WordPress REST | */wp-json/wp/v2/* (non-browser) | T1102.001 |
| Medium API | medium.com/@*/has-recommended (non-browser) | T1102.001 |

**Other C2 Rules (6):**

| Rule | Event Type | What It Detects |
|------|-----------|----------------|
| DNS TXT query | dns_query | TXT record query from non-DNS process |
| Tor SOCKS proxy | connection | Connection to 127.0.0.1:9050 or 9150 |
| SSH login | ssh_login | SSH authentication (inbound or outbound) |
| XPC privileged connect | xpc_connect | Connection to privileged XPC services |
| XProtect malware detection | xprotect_malware | XProtect flagged a binary |
| DNS exfiltration pattern | dns_query | High-entropy subdomain labels (>30 chars) |
| DNS DGA pattern | dns_query | Algorithmically-generated domain names |

### Evasion Rules (9)

| Rule | Event Type | What It Detects | Severity |
|------|-----------|----------------|----------|
| Quarantine bypass | file_setextattr | xattr -d com.apple.quarantine | High |
| TCC.db modification | file_write | Direct TCC database write (not tccutil) | Critical |
| Setuid escalation | setuid | Non-standard setuid call | High |
| Setgid escalation | setgid | Non-standard setgid call | Medium |
| Log deletion | file_unlink | /var/log/* deletion | High |
| Sudo abuse | sudo | Suspicious sudo invocation | Medium |
| Process suspension | proc_suspend_resume | Process freeze/thaw (anti-analysis evasion) | Medium |
| Browser → shell chain | exec | Shell spawned by browser process | High |

### Code Injection Rules (4)

| Rule | Event Type | What It Detects | Severity |
|------|-----------|----------------|----------|
| Remote thread creation | remote_thread_create | Thread injected into another process | Critical |
| Task port acquisition | get_task | task_for_pid on non-self PID | Critical |
| Ptrace attachment | ptrace | Debugger attachment to process | High |
| Kext loading | kext_load | Kernel extension loaded | Critical |

### Exfiltration Rules (3)

| Rule | Event Type | What It Detects | Severity |
|------|-----------|----------------|----------|
| /tmp staging | file_write | Non-standard process writing to /tmp | Medium |
| External volume mount | mount | External volume mounted | Low |
| AWS credential access | file_open | ~/.aws/credentials read | High |

### APT-Specific Rules (10)

| Rule | What It Detects | MITRE |
|------|----------------|-------|
| npm preinstall hook | Package.json preinstall script execution | T1195.002 |
| Dropbox exfiltration | Dropbox API upload from non-Dropbox process | T1567.002 |
| S3 exfiltration | AWS S3 upload from non-AWS CLI | T1567.002 |
| IP lookup (recon) | Connection to ipinfo.io, whatismyip.com, etc. | T1016 |
| Wallpaper change | desktoppr or osascript changing wallpaper | T1491 |
| Crontab hijack | Writing to cron/tabs from non-crontab process | T1053.003 |
| Zshrc hijack | Appending to .zshrc from non-shell process | T1546.004 |
| Filesystem write | Writing to /Library/Filesystems (persistence) | T1547 |
| Mass rename | 10+ file renames in 60 seconds (ransomware) | T1486 |
| /var/tmp staging | Writing executables to /var/tmp | T1074.001 |

### Nation-State Tradecraft Rules (20)

| Rule | Technique | MITRE |
|------|----------|-------|
| Fileless execution | python/ruby/perl reading from stdin (no file arg) | T1059 |
| Inline AppleScript | osascript -e with network/file operations | T1059.002 |
| SSH lateral movement | ssh to internal RFC 1918 addresses | T1021.004 |
| ARD enablement | kickstart -activate enabling screen sharing | T1021.001 |
| VM detection (sysctl) | sysctl hw.model queries from non-system process | T1497.001 |
| VM detection (ioreg) | ioreg queries for VMware/VBox/Parallels strings | T1497.001 |
| Signature removal | codesign --remove-signature | T1553.002 |
| Gatekeeper bypass | spctl --master-disable or --add | T1553.001 |
| Keychain dump | security dump-keychain or export | T1555.001 |
| Directory enumeration | find/ls on sensitive directories from script | T1083 |
| Network discovery | arp/netstat/lsof for network enumeration | T1046 |
| Process discovery | ps aux/lsof from non-terminal process | T1057 |
| Screen capture | screencapture command from non-standard process | T1113 |
| TCC camera grant | Process granted camera access without prompt | T1125 |
| TCC microphone grant | Process granted microphone access without prompt | T1123 |
| Crontab via API | crontab(1) called programmatically | T1053.003 |
| Curl exfiltration | curl POST/PUT to external with file data | T1048 |
| Archive staging | tar/zip creating archives in /tmp | T1560.001 |

---

## Correlation Rules

15 multi-event rules that detect sequences of related events within temporal windows.

### How Correlation Works

Each correlation rule defines:
1. **Events** — An ordered sequence of event types to watch for
2. **Window** — Maximum time between first and last event
3. **Group by** — How to link events (pid or processPath)

```
CorrelationRule {
    events: [EventMatcher, EventMatcher, ...]
    window: TimeInterval
    groupBy: .pid | .processPath

    // Internal state
    partialMatches: [GroupKey: [MatchedEvent]]
}
```

When a SecurityEvent matches the Nth event in a correlation rule's sequence:
1. Find all partial matches for this group key (pid or processPath)
2. If this completes the sequence AND all events are within the time window → fire alert
3. If this advances the sequence → update partial match
4. Partial matches older than the window are pruned

### Complete Rule List

| # | Name | Events (in sequence) | Window | Group By | MITRE |
|---|------|---------------------|--------|----------|-------|
| 1 | Credential theft → exfil | credential_access → network_out | 30s | processPath | T1555 → T1567 |
| 2 | Staged exfil via /tmp | file_write(/tmp) → network_out | 60s | processPath | T1074 → T1048 |
| 3 | Fake password prompt | osascript → file_write → network_out | 30s | pid | T1056.002 → T1048 |
| 4 | Persistence → execution | persistence_write → exec | 120s | processPath | T1547 → T1059 |
| 5 | Memory injection → C2 | mmap → mprotect(RWX) → connection | 120s | pid | T1055 → T1071 |
| 6 | Thread injection + cred theft | remote_thread → credential_access | 60s | pid | T1055 → T1555 |
| 7 | Pegasus-style injection | remote_thread → mprotect(RWX) → c2_connect | 60s | pid | T1055 → T1071 |
| 8 | APT29 kill chain | discovery → credential_access → exfil | 300s | processPath | T1082 → T1555 → T1567 |
| 9 | SSH key theft + lateral | ssh_key_read → ssh_connect | 120s | processPath | T1552.004 → T1021.004 |
| 10 | Evasion chain | persistence_write → cs_invalidated → exec | 180s | processPath | T1547 → T1553 → T1059 |
| 11 | Data collect → archive → exfil | file_read(sensitive) → archive_create → network_out | 300s | processPath | T1005 → T1560 → T1048 |
| 12 | Environmental keying | env_check(sysctl/ioreg) → staging → exec | 120s | processPath | T1497 → T1074 → T1059 |
| 13 | Process hollowing + C2 | hollow_create → c2_connect | 60s | pid | T1055.012 → T1071 |
| 14 | Privesc → persist → payload | privilege_escalation → persistence_write → exec | 300s | pid | T1548 → T1547 → T1059 |
| 15 | Kill defender → execute | security_tool_disable → file_write → exec | 60s | processPath | T1562 → T1105 → T1059 |

---

## Cross-Scanner Correlation (CorrelationEngine)

After all 57 scanners complete a batch scan, the CorrelationEngine looks for processes that were flagged by multiple independent scanners — a strong indicator of actual compromise rather than false positives.

### Algorithm

```
1. Group all ProcessAnomaly results by PID
   (falls back to processPath for scanners that report pid=0)

2. Build reverse map: anomaly.id → scannerID (O(1) lookup)

3. For each process with findings from 2+ scanners:
   a. Run 9 chain checks (specific multi-scanner patterns)
   b. If 3+ scanners flagged this process: emit "Multi-Scanner Threat" (high)

4. Return all correlations
```

### Chain Check Details

Each chain check is a function `(processName, [ProcessAnomaly], Set<scannerID>) -> Correlation?`:

**1. Credential Exfiltration**
- Requires: `credential_access` scanner + (`network_anomaly` OR `cloud_c2` scanner)
- Interpretation: Process is accessing credentials AND communicating externally
- Severity: Critical
- MITRE: T1555 → T1567

**2. Rootkit Behavior**
- Requires: (`hidden_process` OR `stealth` scanner) + (`kext` OR `kernel_integrity` scanner)
- Interpretation: Process is hiding itself AND manipulating the kernel
- Severity: Critical
- MITRE: T1014 → T1547.006

**3. Malware Installation**
- Requires: (`persistence` OR `persistence_monitor` scanner) + (`binary_integrity` OR `dylib_hijack` scanner)
- Interpretation: New persistence item AND unsigned/hijacked binary
- Severity: High
- MITRE: T1547 → T1574

**4. Defense Evasion Chain**
- Requires: (`stealth` OR `hidden_process` scanner) + (`security_evasion` OR `process_integrity` scanner)
- Interpretation: Hiding + actively evading security tools
- Severity: High
- MITRE: T1562 → T1070

**5. Privilege Escalation**
- Requires: `auth_db` scanner + (`persistence` OR `persistence_monitor` OR `kext` scanner)
- Interpretation: Authorization abuse + establishing persistence
- Severity: Critical
- MITRE: T1548 → T1547

**6. C2 Establishment**
- Requires: (`dns_tunnel` OR `covert_channel` scanner) + (`cloud_c2` OR `network_anomaly` scanner)
- Interpretation: Covert communication channel + network C2 infrastructure
- Severity: Critical
- MITRE: T1071 → T1573

**7. Code Injection Chain**
- Requires: (`thread_anomaly` OR `dyld_env` scanner) + (`process_integrity` OR `memory` scanner)
- Interpretation: Injection indicators + confirmed integrity violation
- Severity: High
- MITRE: T1055 → T1574.006

**8. Ransomware + Exfiltration**
- Requires: `ransomware` scanner + (`network_anomaly` OR `cloud_c2` OR `dns_tunnel` scanner)
- Interpretation: Data encryption + external data transfer (double extortion)
- Severity: Critical
- MITRE: T1486 → T1567

**9. Surveillance Chain**
- Requires: `tcc` scanner + (`credential_access` OR `screen_capture` OR `clipboard` scanner)
- Interpretation: TCC privacy abuse + active data collection
- Severity: High
- MITRE: T1005 → T1113

### Multi-Scanner Threshold

Any process flagged by 3 or more independent scanners is automatically classified as a high-confidence multi-scanner threat, regardless of which specific chain pattern it matches. The MITRE chain is constructed by joining all technique IDs from the contributing anomalies.

---

## Fusion Engine

The FusionEngine runs after the CorrelationEngine and bridges the batch scanner path with the real-time alert path.

### Kill Chain Mapping

Every finding is mapped to one of 13 stages:

| Stage | MITRE Technique Prefixes | Scanner IDs |
|-------|-------------------------|-------------|
| **Reconnaissance** | T1595, T1592, T1589 | (real-time rules only) |
| **Initial Access** | T1566, T1190, T1133, T1078 | supply_chain |
| **Execution** | T1059, T1204, T1106, T1053 | lolbin, exploit_tool, script_backdoor |
| **Persistence** | T1547, T1543, T1546, T1574, T1556, T1542 | persistence, persistence_monitor, stealth, kext, boot_security, browser_ext, auth_db |
| **Privilege Escalation** | T1548, T1134, T1068 | entitlement, auth_db |
| **Defense Evasion** | T1562, T1070, T1036, T1027, T1014, T1112, T1055 | masquerade, hidden_process, hidden_files, security_evasion, log_integrity, timestomp, xattr, env_keying, vm_container, dyld_cache |
| **Credential Access** | T1555, T1003, T1110, T1552, T1539, T1056 | credential_access, event_taps, fake_prompt, tcc |
| **Discovery** | T1082, T1057, T1083, T1046 | system_integrity, network_config |
| **Lateral Movement** | T1021, T1570 | (real-time rules only) |
| **Collection** | T1005, T1113, T1115, T1125 | clipboard, screen_capture, staging |
| **Command & Control** | T1071, T1573, T1102, T1095, T1572 | network_anomaly, cloud_c2, dns_tunnel, covert_channel, firewall |
| **Exfiltration** | T1567, T1048, T1041 | dns_tunnel, cloud_c2 |
| **Impact** | T1486, T1485, T1490 | ransomware |

### Entity Extraction

The fusion engine groups findings by three entity types:

1. **Process Entity** — Grouped by PID. All scanner findings, correlation results, and real-time alerts for the same PID are combined.
2. **Signing Identity Entity** — Grouped by code signing ID. Catches the same malware running under different PIDs.
3. **Network Peer Entity** — Grouped by remote address. Identifies C2 infrastructure receiving connections from multiple compromised processes.

### Cross-Domain Scoring

```
For each entity:

1. Collect all evidence (scanner anomalies + correlation results + alerts)

2. Base score = sum of severity weights
   (critical=1.0, high=0.7, medium=0.4, low=0.1)

3. Count distinct evidence domains (scanner types)
   cross_domain_multiplier = 1.0 + 0.3 × (domains - 1)

4. Count distinct kill chain stages covered
   kill_chain_breadth = 1.0 + 0.2 × (stages - 1)

5. final_score = base_score × cross_domain_multiplier × kill_chain_breadth
```

**Example:** A process flagged by:
- `memory` scanner (defenseEvasion, severity=high, 0.7)
- `network_anomaly` scanner (c2, severity=medium, 0.4)
- `credential_access` scanner (credentialAccess, severity=high, 0.7)
- 1 real-time alert (persistence, severity=high, 0.7)

Base score: 0.7 + 0.4 + 0.7 + 0.7 = 2.5
Cross-domain: 1.0 + 0.3 × (4-1) = 1.9
Kill chain breadth: 1.0 + 0.2 × (4-1) = 1.6 (4 stages: defenseEvasion, c2, credentialAccess, persistence)
Final: 2.5 × 1.9 × 1.6 = **7.6** (very high threat)

### Campaign Detection

After scoring all entities, the fusion engine clusters them into campaigns:

```
1. Sort all entities by timestamp of first evidence

2. Sliding window: 1 hour
   Group entities whose evidence overlaps within the window

3. For each group with 2+ entities AND 3+ kill chain stages:
   → Declare a campaign

4. Classify campaign type:
   If credentialAccess + exfiltration stages → "Data Theft Campaign"
   If persistence + execution + c2 stages   → "Implant Campaign"
   If impact stage present                  → "Destructive Campaign"
   If defenseEvasion in majority            → "Evasion Campaign"
   If 5+ stages covered                    → "Advanced Persistent Threat"
   Default                                  → "Unknown Campaign"

5. Campaign severity = max(entity severities)
```

---

## MITRE ATT&CK Coverage Summary

Iris detects 130+ unique MITRE ATT&CK technique IDs. The following table shows coverage by tactic:

| Tactic | Techniques | Primary Detectors |
|--------|-----------|-------------------|
| Reconnaissance | T1595, T1592, T1589 | Nation-state tradecraft rules (ioreg, sysctl, network discovery) |
| Initial Access | T1566, T1190, T1133, T1078 | Supply chain auditor, real-time rules |
| Execution | T1059.*, T1204, T1106, T1053.* | LOLBin detector, script backdoor scanner, exploit tool detector |
| Persistence | T1547.*, T1543.*, T1546.*, T1574.*, T1556.*, T1542, T1176 | Persistence scanner (13 categories), persistence monitor, stealth scanner, kext anomaly, boot security |
| Privilege Escalation | T1548.*, T1134, T1068 | Authorization DB monitor, entitlement scanner, stealth+auth checks |
| Defense Evasion | T1562.*, T1070.*, T1036.*, T1027, T1014, T1553.*, T1564.*, T1497.* | Masquerade, hidden process, stealth, security evasion, log integrity, timestomp, xattr, env keying |
| Credential Access | T1555.*, T1003, T1110, T1552.*, T1539, T1056.* | Credential access detector, event tap scanner, fake prompt, TCC monitor |
| Discovery | T1082, T1057, T1083, T1046 | System integrity scanner, network config auditor, nation-state rules |
| Lateral Movement | T1021.*, T1570 | SSH correlation rules, nation-state tradecraft rules |
| Collection | T1005, T1113, T1115, T1125 | Clipboard scanner, screen capture, staging detector |
| Command & Control | T1071.*, T1573, T1102.*, T1095, T1572 | Network anomaly, cloud C2, DNS tunneling, covert channel |
| Exfiltration | T1567.*, T1048.*, T1041 | DNS tunneling, cloud C2, correlation rules |
| Impact | T1486, T1485, T1490 | Ransomware detector, crash report analyzer |

---

## Source Files

All detection engine files are in `Packages/IrisSecurity/Sources/IrisSecurity/`:

### Engine/
| File | Purpose |
|------|---------|
| DetectionEngine.swift | Actor that evaluates SecurityEvents against rules |
| SecurityEventBus.swift | Polls extensions, normalizes events, feeds DetectionEngine |
| DetectionRule.swift | SimpleDetectionRule protocol and field matching |
| CorrelationRule.swift | Multi-event temporal rule with partial match state |
| CorrelationEngine.swift | Cross-scanner pattern detection (9 chain checks) |
| CorrelationState.swift | Shared state for correlation rule evaluation |
| FusionEngine.swift | Kill chain mapping, entity scoring, campaign detection |
| AlertStore.swift | Ring buffer alert storage with dedup and notifications |
| ScanSession.swift | SwiftUI-observable scan orchestration wrapper |
| ScannerRegistry.swift | ScannerEntry type, tier enum, scan context |
| ScannerRegistry+Entries.swift | All 57 scanner registrations by tier |
| ESEventDecoder.swift | Endpoint Security event deserialization |

### Rules/
| File | Rules | Category |
|------|-------|----------|
| CredentialTheftRules.swift | 7 | Credential file access detection |
| PersistenceRules.swift | 6 | Persistence mechanism creation |
| C2Rules.swift | 19 | Cloud C2, dead drops, DNS, Tor, SSH |
| EvasionRules.swift | 9 | Quarantine bypass, TCC mod, log deletion |
| InjectionRules.swift | 4 | Remote threads, task ports, ptrace, kext |
| ExfiltrationRules.swift | 3 | /tmp staging, volume mount, AWS creds |
| APTRules.swift | 10 | Nation-state-specific patterns |
| NationStateRules.swift | 20 | Advanced tradecraft (fileless, VM detect, etc.) |
| CorrelationRules.swift | 15 | Temporal multi-event correlation definitions |
| RuleLoader.swift | — | Aggregates all rules for DetectionEngine |
