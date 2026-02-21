# Iris

A macOS endpoint detection and response system built on kernel-level telemetry. Iris monitors process execution, network traffic, DNS resolution, and filesystem activity through four system extensions, correlates findings across 57 security scanners, and maps threats to the MITRE ATT&CK framework in real time.

<img width="1055" height="836" alt="image" src="https://github.com/user-attachments/assets/6a650660-4397-499f-8a5d-46165b90aa8a" />

<img width="1287" height="868" alt="image" src="https://github.com/user-attachments/assets/fe2705b8-a0d3-47cf-8722-3005373d6525" />

<img width="950" height="824" alt="image" src="https://github.com/user-attachments/assets/0891c192-ec38-4b29-9d47-b39a033a0203" />

<img width="1303" height="887" alt="image" src="https://github.com/user-attachments/assets/e9532477-95ab-4f35-91e1-8ad382c11f09" />

<img width="1724" height="1110" alt="image" src="https://github.com/user-attachments/assets/9d3e3485-a756-4e71-9208-5f32579325be" />

<img width="1728" height="1117" alt="image" src="https://github.com/user-attachments/assets/8d7ec93e-4415-4eac-9bdd-91ee8f1538bf" />

---

## What Iris Does

Iris operates at every layer of the macOS security stack:

**Process Monitoring** — Subscribes to 23 Endpoint Security framework event types (exec, fork, exit, file operations, privilege escalation, code injection, memory mapping) and maintains a live process table with full ancestry chains, code signing status, and resource consumption.

**Network Interception** — A transparent proxy intercepts all outbound TCP and UDP traffic. HTTPS connections are decrypted via per-host TLS MITM certificates, parsed as HTTP, and logged with process attribution. Plaintext HTTP is captured directly. Per-flow firewall rules can block or allow traffic by process, domain, or port.

**DNS Visibility** — A DNS proxy intercepts all system DNS queries (both UDP and TCP), resolves them via DNS-over-HTTPS (Cloudflare, Google, or Quad9), and records every query with the originating process, response code, answer records, TTL, and latency.

**Threat Detection** — 57 scanners organized in three performance tiers analyze processes, memory regions, persistence mechanisms, kernel extensions, network behavior, credentials, browser extensions, boot security, and more. Findings flow through a correlation engine (9 multi-stage attack chain patterns), a fusion engine (13-stage kill chain mapping with cross-domain scoring), and 79 real-time detection rules with 15 temporal correlation rules.

**MITRE ATT&CK Coverage** — 130+ unique technique IDs across all 14 kill chain stages, from reconnaissance through impact. Every finding carries its technique ID, scanner ID, enumeration method, and structured evidence.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         Iris.app (UI)                            │
│                                                                  │
│  ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌─────────────┐  │
│  │ Process    │  │ Network    │  │ DNS      │  │ Security    │  │
│  │ Monitor    │  │ Monitor    │  │ Monitor  │  │ Hub         │  │
│  └─────┬──────┘  └─────┬──────┘  └────┬─────┘  └──────┬──────┘  │
│        │ XPC           │ XPC          │ XPC           │         │
└────────┼───────────────┼──────────────┼───────────────┼──────────┘
         │               │              │               │
         ▼               ▼              ▼               ▼
   ┌──────────┐   ┌───────────┐   ┌──────────┐   ┌───────────┐
   │ Endpoint │   │ Proxy     │   │ DNS      │   │ Batch     │
   │ Security │   │ Extension │   │ Extension│   │ Scanners  │
   │ Extension│   │           │   │          │   │ (in-app)  │
   │          │   │ TLS MITM  │   │ DoH      │   │           │
   │ 23 event │   │ HTTP parse│   │ Query    │   │ 57 scans  │
   │ types    │   │ Firewall  │   │ logging  │   │ per cycle │
   └──────────┘   └───────────┘   └──────────┘   └───────────┘
```

The main app communicates with system extensions exclusively through XPC over Mach services. Extensions run as separate processes with their own entitlements and sandboxes. The batch scanner system runs within the app process and does not require an extension.

### System Extensions

| Extension | Framework | What It Does |
|-----------|-----------|--------------|
| **IrisEndpointExtension** | Endpoint Security | Subscribes to 23 ES event types. Maintains a live process table in a ring buffer (5,000 process events + 10,000 security events). Reports process lifecycle, file operations, privilege escalation, code injection, authentication, and memory operations. |
| **IrisProxyExtension** | NETransparentProxyProvider | Claims all outbound TCP/UDP flows. Routes by port: 443 → TLS MITM + HTTP parsing, 80 → plaintext HTTP parsing, 53 → DNS-over-HTTPS relay, all others → passthrough with byte counting. Evaluates firewall rules per-flow. Stores captured flows (max 10,000) and DNS queries (max 10,000) for app polling. |
| **IrisDNSExtension** | NEDNSProxyProvider | Intercepts all system DNS resolution (UDP and TCP). Converts to DNS-over-HTTPS via configurable upstream (Cloudflare/Google/Quad9). Uses IP addresses directly for bootstrap to avoid the DNS chicken-and-egg problem. Records query domain, type, response code, answers, TTL, latency, and originating process. |

### Packages

| Package | Lines | What It Contains |
|---------|-------|------------------|
| **IrisSecurity** | 22,652 | The detection engine. 57 scanners, 79 detection rules, 15 correlation rules, 9 correlation chain patterns, fusion engine with kill chain mapping, threat intelligence databases, AlertStore (ring buffer), SecurityEventBus. Also includes 15+ security-focused SwiftUI views. |
| **IrisNetwork** | 6,540 | Network monitoring UI. Connection list with geolocation enrichment (GeoIP, GreyNoise, AbuseIPDB, Shodan), firewall rule management, IP detail popovers with world map visualization. SecurityStore polls proxy extension via XPC. |
| **IrisProcess** | 3,113 | Process tree visualization, per-process resource tracking (CPU, memory, threads), process detail views with ancestry chains and open file descriptors. |
| **IrisDNS** | 2,240 | DNS query monitor with search/filter, DoH client (RFC 8484), DNS message parser (RFC 1035 with compression pointer handling), query statistics dashboard. |
| **IrisApp** | 2,152 | Main application shell. Home screen with circular stone navigation menu, settings views for each extension, Metal rendering pipeline. Rust FFI bridges for batch crypto ops, DNS parsing, and Mach-O parsing. |
| **IrisSatellite** | 2,487 | 3D satellite orbital visualization rendered with Metal. |
| **IrisProxy** | 1,692 | HTTP flow capture UI. Flow list with method, URL, status code, timing. Request/response detail views with headers, body preview, and raw hex. |
| **IrisShared** | 1,337 | ExtensionManager (install/uninstall/status for all extensions), NetworkFilterManager, DNSProxyManager, TransparentProxyManager. XPC protocol definitions. Shared utilities (ByteFormatter, AtomicFlag). |
| **IrisCertificates** | 1,317 | Root CA generation, per-host leaf certificate creation, keychain management for TLS MITM. |
| **IrisDisk** | 991 | Disk usage scanner with tree visualization. |
| **IrisWiFi** | 2,064 | WiFi network monitoring, BSSID scanning, signal strength analysis. |

### Rust Component

A static library (`rust/iris-parsers`, 7 files, 1,584 lines) provides high-performance operations via C FFI:

| Function | What It Does |
|----------|--------------|
| `iris_http_parse_request` / `_response` | HTTP/1.1 request and response parsing for the proxy extension |
| `iris_dns_parse` | RFC 1035 DNS wire format parser with compression pointer handling |
| `iris_macho_parse` | Mach-O binary header and load command parsing |
| `iris_file_entropy_full` | Shannon entropy, chi-square, Monte Carlo, and magic byte detection |
| `iris_sha256_batch` | Batch SHA256 hashing for scanner use |

The library compiles arm64-only. All Xcode builds must target arm64.

---

## Detection Engine

Iris runs two parallel detection paths that converge in the UI.

### Real-Time Detection Path

```
ES Events (23 types)                Network Events            DNS Events
       │                                  │                       │
       ▼                                  ▼                       ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │                    SecurityEventBus                              │
  │              (polls extensions every 1 second)                  │
  │              (normalizes into SecurityEvent)                    │
  └──────────────────────────┬──────────────────────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │                      DetectionEngine (actor)                     │
  │                                                                  │
  │  ┌─────────────────────┐     ┌──────────────────────────────┐   │
  │  │ 79 Simple Rules     │     │ 15 Correlation Rules         │   │
  │  │                     │     │                              │   │
  │  │ Single-event match: │     │ Multi-event temporal match:  │   │
  │  │ event type + field  │     │ sequence of events within    │   │
  │  │ predicates          │     │ a time window, grouped by    │   │
  │  │                     │     │ PID or processPath           │   │
  │  └─────────┬───────────┘     └───────────────┬──────────────┘   │
  │            │                                 │                  │
  │            └──────────┬──────────────────────┘                  │
  └───────────────────────┼─────────────────────────────────────────┘
                          │
                          ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │                        AlertStore                                │
  │                                                                  │
  │  Ring buffer: 5,000 max alerts                                  │
  │  Dedup window: 60 seconds (same rule + same process = skip)     │
  │  System notifications for critical and high severity            │
  └──────────────────────────────────────────────────────────────────┘
```

#### Simple Detection Rules (79 rules, 8 modules)

Each rule matches a single SecurityEvent by event type and field predicates:

**Credential Theft (7 rules)** — Detects access to Chrome Login Data, Keychain databases, browser cookie stores, Firefox credential files, cryptocurrency wallet directories, SSH private keys, and authorization database reads.

**Persistence (6 rules)** — Detects writes to LaunchAgent/LaunchDaemon plists, shell profile modifications (.zshrc, .bashrc, .bash_profile), Xcode build phase injection, and crontab edits.

**Command & Control (19 rules)** — Monitors for connections to 7 known cloud C2 domains (Dropbox API, AWS S3, OneDrive, pCloud), 6 dead drop resolver services (Telegram API, Pastebin, GitHub Gist, bit.ly, WordPress REST, Medium API), DNS TXT record queries from non-DNS processes, Tor SOCKS proxy connections, SSH logins, XPC privileged connects, XProtect malware detections, DNS exfiltration patterns, and domain generation algorithm (DGA) indicators.

**Evasion (9 rules)** — Catches quarantine attribute bypass (xattr -d com.apple.quarantine), TCC.db direct modification, setuid/setgid privilege changes, system log deletion, sudo abuse, process suspension/resumption, and browser-to-shell process spawning chains.

**Code Injection (4 rules)** — Monitors for remote thread creation (task_threads), Mach task port acquisition (task_for_pid), ptrace attachment, and kernel extension loading.

**Exfiltration (3 rules)** — Detects /tmp file staging by non-standard processes, external volume mounts, and AWS credential file access.

**APT-Specific (10 rules)** — Targets nation-state tradecraft: npm preinstall hook exploitation, Dropbox/S3 exfiltration paths, IP lookup services (reconnaissance), wallpaper changes (defacement), crontab/zshrc hijacking, /Library/Filesystems writes, mass file rename patterns (ransomware), and /var/tmp staging.

**Nation-State Tradecraft (20 rules)** — Detects fileless execution (interpreters reading from stdin), inline AppleScript execution, SSH lateral movement, Apple Remote Desktop enablement, VM detection checks (sysctl/ioreg), code signature manipulation (codesign --remove-signature), Gatekeeper bypass (spctl), keychain dumps, directory/network/process discovery commands, screen capture utilities, TCC grants for camera/microphone, and curl-based exfiltration.

#### Correlation Rules (15 rules)

Multi-event rules track sequences of events within temporal windows:

| Rule | Events | Window | Groups By |
|------|--------|--------|-----------|
| Credential theft → exfiltration | credential_access then network_out | 30s | processPath |
| Staged exfiltration via /tmp | file_write(/tmp) then network_out | 60s | processPath |
| Fake password prompt chain | osascript then file_write then network_out | 30s | pid |
| Persistence → execution | persistence_write then exec | 120s | processPath |
| Memory injection → C2 | mmap → mprotect → connection | 120s | pid |
| Thread injection + credential theft | remote_thread then credential_access | 60s | pid |
| Pegasus-style injection chain | remote_thread → shellcode(mprotect) → C2 | 60s | pid |
| Recon → credential → exfil (APT29) | discovery → credential_access → exfil | 300s | processPath |
| SSH key theft + lateral movement | ssh_key_read then ssh_connect | 120s | processPath |
| Evasion chain | persistence → signature_strip → exec | 180s | processPath |
| Data collection → archive → exfil | data_access → archive_create → network_out | 300s | processPath |
| Environmental keying chain | env_check → staging → exec | 120s | processPath |
| Process hollowing + C2 | hollow then c2_connect | 60s | pid |
| Privilege escalation chain | privesc → persistence → payload_exec | 300s | pid |
| Kill defender → drop → execute | defender_disable → file_write → exec | 60s | processPath |

### Batch Detection Path

```
ProcessSnapshot + [NetworkConnection]
              │
              ▼
       SecurityAssessor
              │
              ├──→ 17 Fast scanners  (parallel)  ~2-5ms each
              │         │
              │         ▼ (wait for fast to finish)
              ├──→ 25 Medium scanners (parallel)  ~50-500ms each
              │         │
              │         ▼ (wait for medium to finish)
              └──→ 15 Slow scanners   (parallel)  >500ms each
                        │
                        ▼
                  [ScannerResult]  (one per scanner: id + [ProcessAnomaly])
                        │
                        ▼
                 CorrelationEngine
                 (groups by PID, detects 9 multi-scanner patterns)
                        │
                        ▼
                   FusionEngine
                   (maps to 13-stage kill chain,
                    scores with cross-domain multipliers,
                    detects multi-entity campaigns)
                        │
                        ▼
                   FusionResult
                   (entities + campaigns + per-stage evidence)
```

### Correlation Engine

Groups all scanner findings by PID and looks for processes flagged by multiple independent scanners:

| Attack Pattern | Required Scanner Combination | MITRE Chain | Severity |
|---------------|------------------------------|-------------|----------|
| Credential Exfiltration | credential_access + (network_anomaly \| cloud_c2) | T1555 → T1567 | Critical |
| Rootkit Behavior | (hidden_process \| stealth) + (kext \| kernel_integrity) | T1014 → T1547.006 | Critical |
| Malware Installation | (persistence \| persistence_monitor) + (binary_integrity \| dylib_hijack) | T1547 → T1574 | High |
| Defense Evasion Chain | (stealth \| hidden_process) + (security_evasion \| process_integrity) | T1562 → T1070 | High |
| Privilege Escalation | auth_db + (persistence \| persistence_monitor \| kext) | T1548 → T1547 | Critical |
| C2 Establishment | (dns_tunnel \| covert_channel) + (cloud_c2 \| network_anomaly) | T1071 → T1573 | Critical |
| Code Injection Chain | (thread_anomaly \| dyld_env) + (process_integrity \| memory) | T1055 → T1574.006 | High |
| Ransomware + Exfiltration | ransomware + (network_anomaly \| cloud_c2 \| dns_tunnel) | T1486 → T1567 | Critical |
| Surveillance Chain | tcc + (credential_access \| screen_capture \| clipboard) | T1005 → T1113 | High |

Any process flagged by **3 or more** independent scanners is automatically classified as a multi-scanner threat with high severity, regardless of which specific pattern it matches.

### Fusion Engine

The fusion engine bridges the batch scanner path with the real-time alert path, providing a unified threat assessment:

**Kill Chain Mapping** — Maps 47 MITRE technique prefixes and all 57 scanner IDs to 13 kill chain stages (reconnaissance through impact). This creates a single view of how far an attacker has progressed.

**Entity Extraction** — Groups findings by three entity types: process (by PID), signing identity (by code signing ID), and network peer (by remote address). Each entity accumulates evidence from all scanners and rules that flagged it.

**Cross-Domain Scoring:**
```
final_score = base_score × cross_domain_multiplier × kill_chain_breadth

cross_domain_multiplier = 1.0 + 0.3 × (evidence_sources - 1)
kill_chain_breadth      = 1.0 + 0.2 × (kill_chain_stages - 1)
```

A process flagged by one scanner in one stage gets a 1.0x multiplier. A process flagged by four scanners across five kill chain stages gets `1.0 + 0.3×3 = 1.9x` cross-domain and `1.0 + 0.2×4 = 1.8x` breadth — a combined 3.42x amplification.

**Campaign Detection** — Clusters related entities within 1-hour temporal windows. When 2 or more entities collectively span 3 or more kill chain stages, the fusion engine declares a campaign and classifies it:

| Campaign Type | Pattern |
|--------------|---------|
| Data Theft | credentialAccess + exfiltration stages present |
| Implant | persistence + execution + c2 stages present |
| Destructive | impact stage present |
| Evasion | defenseEvasion in majority of evidence |
| Advanced Persistent Threat | 5+ kill chain stages covered |

---

## Scanners

57 scanners in three performance tiers. Every scanner returns `[ProcessAnomaly]` — a standardized result type carrying PID, process name and path, parent PID, technique name, human-readable description, severity level, MITRE ATT&CK technique ID, scanner ID, enumeration method, and structured evidence array.

### Fast Tier — 17 Scanners

Process-memory inspection only. No disk I/O. Each scanner completes in ~2-5ms.

| ID | Scanner | What It Detects | Enumeration Method |
|----|---------|----------------|-------------------|
| `lolbin` | LOLBin Detector | Living-off-the-land binary abuse (curl, osascript, python, ruby, perl, etc.) | ProcessSnapshot + known-LOLBin signature database |
| `stealth` | Stealth Scanner | Hidden LaunchAgents, PAM module insertion, sudoers edits, SUID binaries, DYLD injection, SSH authorized_key changes, at jobs, emond rules, quarantine xattr bypass | Multi-module enumeration across 9 stealth categories |
| `process_integrity` | Process Integrity | Unsigned processes running from unusual paths, tampered process memory, code injection artifacts | mach_vm_region + SecCodeCheckValidity |
| `credential_access` | Credential Access | Credential dumping tools (mimikatz patterns), password extraction payloads, keychain access by non-standard processes | ProcessSnapshot fields + memory pattern matching |
| `dyld_env` | DYLD Injection | DYLD_INSERT_LIBRARIES, DYLD_FRAMEWORK_PATH, DYLD_LIBRARY_PATH environment variable abuse | Process environment variable enumeration |
| `masquerade` | Masquerade Detector | Process name spoofing (e.g., "Finder" running from /tmp), Unicode homograph attacks, font confusion | Name/path comparison + Unicode analysis |
| `hidden_process` | Hidden Processes | Processes hidden from ps/Activity Monitor | processor_set_tasks() XNU kernel API bypass |
| `memory` | Memory Scanner | RWX memory regions (shellcode staging), reflective Mach-O binary loading in anonymous memory | mach_vm_region + MH_MAGIC_64 header detection |
| `fake_prompt` | Fake Prompt Detector | Fake authentication dialogs (phishing for user credentials) | Window title + process identity analysis |
| `exploit_tool` | Exploit Tool Detector | Known exploit frameworks (Metasploit, Cobalt Strike, Empire, Mythic agents) | Binary path + code signing identity matching |
| `thread_anomaly` | Thread Anomaly | Anomalous thread counts indicating code injection | proc_pidinfo(PROC_PIDTASKINFO) thread enumeration |
| `clipboard` | Clipboard Scanner | Sensitive data left in pasteboard (API keys, passwords, PII patterns) | NSPasteboard content inspection |
| `network_anomaly` | Network Anomaly | C2 beaconing (coefficient of variation analysis), DNS DGA patterns, DNS exfiltration indicators, unusual port usage | Connection timing + statistical pattern analysis |
| `cloud_c2` | Cloud C2 Detector | C2 channels over Slack, Discord, Telegram, Dropbox, OneDrive, Google Drive | Connection endpoint + cloud service hostname matching |
| `env_keying` | Environmental Keying | Malware that checks for VM/sandbox/analysis environments before activating | System configuration fingerprint analysis |
| `process_hollowing` | Process Hollowing | Replaced process images, process memory inconsistent with on-disk binary | Memory entrypoint + binary comparison |
| `inline_hook` | Inline Hook Detector | ARM64 function trampolines/detours in 7 critical system libraries | LDR X16/X17 + BR instruction pattern scan via mach_vm_read_overwrite |

### Medium Tier — 25 Scanners

File reads, plist parsing, SQLite queries. Each scanner completes in ~50-500ms.

| ID | Scanner | What It Detects | Enumeration Method |
|----|---------|----------------|-------------------|
| `xpc_services` | XPC Services | Suspicious XPC service definitions, privilege escalation via XPC | launchctl export + plist parsing |
| `mach_services` | Mach Services | Suspicious Mach service registrations, IPC hijacking | Mach bootstrap namespace inspection |
| `kext` | Kext Anomaly | Unsigned kernel extensions, non-Apple kexts not in IPSW baseline | /System/Library/Extensions enumeration + codesign validation |
| `auth_db` | Authorization DB | Modified authorization rules, privilege escalation rules | authorization.plist parsing + rule inspection |
| `persistence` | Persistence Scanner | 13 persistence categories: LaunchAgents, LaunchDaemons, login items, cron jobs, kernel extensions, system extensions, browser extensions, authorization plugins, login/logout hooks, startup scripts, shell profile configs, DYLD insert entries, periodic scripts | FileManager enumeration + plist parsing + code signing |
| `event_taps` | Event Taps | Keyboard/mouse event taps (keylogger detection) | CGGetEventTapList → CGEventTapInformation |
| `tcc` | TCC Monitor | Suspicious TCC privacy grants (camera, microphone, screen recording, full disk, accessibility) | TCC.db SQLite query + code signing validation |
| `ransomware` | Ransomware Detector | High-entropy file creation, mass file modification patterns | ES_EVENT_TYPE_NOTIFY_WRITE entropy analysis |
| `system_integrity` | System Integrity | AMFI disabled, insecure kernel boot, SIP disabled, custom boot-args | sysctl queries + NVRAM inspection |
| `network_config` | Network Config | DNS hijacking configurations, suspicious routing rules, proxy settings | Route table enumeration + resolver config |
| `staging` | Staging Detector | Staged payloads in /tmp and /var/tmp, artifacts from 214+ known malware families targeting browser credentials, crypto wallets, SSH keys, cloud credentials | Temporary file enumeration + threat intel path matching |
| `xattr` | Xattr Abuse | Missing quarantine xattr on downloaded files, resource fork abuse | Extended attribute scan of binaries |
| `hidden_files` | Hidden Files | Hidden files in critical paths (home directory, /usr/local, /Library) | Dot-file enumeration + content inspection |
| `usb` | USB Devices | USB implants (BadUSB, Rubber Ducky, O.MG Cable), suspicious Billboard devices | IOKit USB device enumeration |
| `log_integrity` | Log Integrity | Tampered system logs, deleted log files, modified timestamps | System log enumeration + anomaly detection |
| `screen_capture` | Screen Capture | Unauthorized screen recording, screenshot capture processes | CGDisplayStream + process validation |
| `covert_channel` | Covert Channel | HTTP header-based covert channels, timing channels | Network traffic pattern analysis |
| `firewall` | Firewall Auditor | Firewall bypass rules, unauthorized port forwarding | pfctl rule inspection + policy analysis |
| `mach_port` | Mach Port Scanner | Malicious Mach port registrations, IPC interception attempts | Bootstrap namespace enumeration |
| `script_backdoor` | Script Backdoors | Backdoored shell configs, malicious command substitution, suspicious alias definitions | Shell script inspection + pattern matching |
| `download_provenance` | Download Provenance | Downloaded files from suspicious URLs, missing quarantine flags | Download metadata + URL reputation |
| `crash_reports` | Crash Reports | Exploitation artifacts in crash logs, debugger attachment evidence | Crash log parsing + exception analysis |
| `dns_tunnel` | DNS Tunneling | DNS exfiltration channels (Iodine, dns2tcp, DNSCat), high-entropy subdomains | DNS query entropy + subdomain length analysis |
| `persistence_monitor` | Persistence Monitor | New or modified persistence items since last scan | SHA256 snapshot diff against baseline |
| `timestomp` | Timestomp Detector | File timestamp manipulation via futimes/utimes | POSIX timestamp consistency checks |

### Slow Tier — 15 Scanners

Code signing verification, deep binary parsing, network-dependent checks. Each scanner takes >500ms.

| ID | Scanner | What It Detects | Enumeration Method |
|----|---------|----------------|-------------------|
| `binary_integrity` | Binary Integrity | Unsigned binaries, ad-hoc signatures, invalid signatures, dangerous entitlements (get-task-allow, com.apple.private.*, cs.disable-library-validation) | SecStaticCodeCreateWithPath + codesign verification |
| `dylib_hijack` | Dylib Hijack | Rpath hijacking, writable library paths, phantom load commands | otool -L + LC_LOAD_DYLIB + rpath analysis |
| `certificate` | Certificate Auditor | Suspicious root certificates, self-signed CAs, expired certificates in trust store | Keychain enumeration + certificate validation |
| `browser_ext` | Browser Extensions | Malicious/suspicious browser extensions in Chrome, Firefox, Safari | Extension directory scan + manifest.json parsing |
| `entitlement` | Entitlement Scanner | Running processes with dangerous entitlements (get-task-allow, task_for_pid-allow, disable-library-validation) | SecCodeCopySigningInformation entitlement extraction |
| `security_evasion` | Security Tool Evasion | Anti-analysis tools, debugger detection code, sandbox escape indicators | Binary analysis + behavioral pattern matching |
| `vm_container` | VM/Container Detector | Virtual machines (VMware, Parallels, VirtualBox), Docker containers, hypervisor presence | Hardware fingerprint + container runtime checks |
| `boot_security` | Boot Security | Secure boot disabled, NVRAM boot-args tampering, SIP disabled, firmware-level implants, SEP compromise indicators | bputil + IOKit NVRAM reads + SEP status |
| `kernel_integrity` | Kernel Integrity | Unknown MACF policies (rootkit indicator), kext policy database violations, untrusted trust caches | MACF policy sysctl + kext policy DB + trust cache validation |
| `dyld_cache` | Dyld Cache | Corrupted or manipulated dyld shared cache, ASLR bypass indicators | Shared cache verification + hash comparison |
| `iokit_driver` | IOKit Drivers | Malicious IOKit drivers, unauthorized device firmware modifications | IOKit driver enumeration + code signature verification |
| `app_audit` | Application Auditor | Trojanized applications, fake system apps, apps without proper provenance | Bundle structure + entitlements + code signing + baseline comparison |
| `browser_history` | Browser History | C2 communication artifacts, reconnaissance browsing patterns | SQLite inspection (Chrome History, Safari, Firefox places.sqlite) |
| `supply_chain` | Supply Chain Auditor | Compromised packages in npm, pip, Homebrew | Package manager audit + known-vulnerable package databases |
| `phantom_dylib` | Phantom Dylib | Missing dylibs referenced by LC_LOAD_DYLIB load commands (hijacking opportunity) | Load command enumeration + filesystem path existence check |

---

## Network Interception

### TLS Man-in-the-Middle

Iris decrypts HTTPS traffic using a hybrid TLS architecture:

```
Browser                    IrisProxyExtension                    Real Server
   │                              │                                   │
   │  ClientHello ──────────────► │                                   │
   │                              │                                   │
   │  ◄──── ServerHello ──────── │                                   │
   │        (per-host cert        │                                   │
   │         from Iris CA)        │                                   │
   │                              │                                   │
   │  TLS 1.2 established ◄────► │                                   │
   │                              │ ──── ClientHello ───────────────► │
   │  Decrypted HTTP              │                                   │
   │  request flows               │ ◄─── ServerHello ─────────────── │
   │  through RustHTTPParser      │      (real server cert)           │
   │                              │                                   │
   │                              │ TLS 1.3 established ◄──────────► │
   │                              │                                   │
   │  ◄──── HTTP response ─────  │ ◄─── HTTP response ────────────  │
   │  (re-encrypted with          │ (decrypted, parsed,               │
   │   Iris cert)                 │  captured to flow store)          │
```

**Client-facing (TLSSession.swift):** Uses `SSLCreateContext` with custom `SSLSetIOFuncs` I/O callbacks that read raw bytes from `NEAppProxyTCPFlow`. Presents a per-host leaf certificate generated on demand by `TLSInterceptor` (2048-bit RSA, X.509 v3 with Subject Alternative Name). TLS 1.2 maximum — acceptable because the client is on the same machine.

**Server-facing (NWConnection):** Standard `NWConnection` with TLS parameters. Full TLS 1.3 support to real servers. Accepts all server certificates (we are the MITM).

**Per-host certificate generation flow:**
1. Extract SNI hostname from `NEAppProxyTCPFlow.remoteHostname`
2. Check in-memory certificate cache
3. On miss: generate random 16-byte serial, build X.509 v3 cert with basicConstraints (CA:false), keyUsage (digitalSignature, keyEncipherment), extKeyUsage (serverAuth), and SAN (DNS name or IP)
4. Sign with Iris root CA private key using SHA256withRSA
5. Cache SecIdentity for future connections to same host

**Why SSLCreateContext?** It is the only Apple API that supports arbitrary I/O callbacks for TLS termination on raw byte streams. `NWConnection` cannot accept bytes from `NEAppProxyTCPFlow`. The API is deprecated but has no functional replacement. Future upgrade path: SwiftNIO + swift-nio-ssl (BoringSSL) with `EmbeddedChannel`.

**HTTP pipelining:** The proxy handles HTTP keep-alive connections with multiple request/response pairs. After capturing a complete HTTP exchange, it resets parsing state and checks for buffered data from the next pipelined request.

### DNS-over-HTTPS

```
Application DNS query (UDP or TCP port 53)
       │
       ▼
IrisDNSExtension (NEDNSProxyProvider)
       │
       ├─ Parse DNS wire format (RFC 1035)
       ├─ Extract: domain, type, class
       │
       ▼
DoHClient (embedded in extension)
       │
       ├─ POST https://1.1.1.1/dns-query
       │  Content-Type: application/dns-message
       │  Body: original DNS wire format
       │
       ▼
Cloudflare / Google / Quad9 response
       │
       ├─ Parse DNS response
       ├─ Record: domain, type, rcode, answers, TTL, latency, process
       │
       ▼
Return DNS wire format to application
```

Bootstrap uses IP addresses directly — the DoH server addresses (1.1.1.1, 8.8.8.8, 9.9.9.9) are hardcoded to avoid a DNS lookup loop.

### Per-Flow Firewall

The proxy extension evaluates firewall rules for every claimed flow before relaying traffic:

```swift
struct SecurityRule {
    let action: Action       // .allow or .block
    let processPath: String? // regex or exact match
    let domain: String?      // regex or wildcard
    let port: UInt16?        // specific port
    let isActive: Bool
    let expiresAt: Date?     // optional auto-expiration
}
```

Rules are evaluated in order. First match wins. Rules persist to disk across extension restarts. Expired rules are cleaned up on a 60-second timer.

---

## Evidence-Based Scoring

All threat scoring follows these invariants:

1. **Weights 0.0 to 1.0 only.** Nothing subtracts from suspicion. No negative weights exist anywhere in the system.
2. **Everything is visible.** Every finding appears in the audit list, even with a zero score. There are no suppressed results.
3. **Baseline is context, not a discount.** `isBaselineItem` is a display label. It does not reduce the score.
4. **Score = sum of weights, clamped to [0, 1].** Severity thresholds: 0.8+ critical, 0.6-0.8 high, 0.3-0.6 medium, <0.3 low.
5. **Baseline data from IPSW.** The macOS 26.2 (25C56) baseline contains 418 daemons, 460 agents, 674 kexts, and 12 authorization plugins.

---

## XPC Communication

All app-to-extension communication uses Mach XPC services with a delta protocol:

| Service Name | Protocol | Data Format |
|-------------|----------|-------------|
| `99HGW2AR62.com.wudan.iris.endpoint.xpc` | EndpointXPCProtocol | JSON-encoded [Data] |
| `99HGW2AR62.com.wudan.iris.proxy.xpc` | ProxyXPCProtocol | JSON-encoded [Data] |
| `99HGW2AR62.com.wudan.iris.dns.xpc` | DNSXPCProtocol | JSON-encoded [Data] |

**Delta protocol:** Each poll sends the last-seen sequence number. The extension returns only entries with sequence numbers greater than the requested value. This eliminates redundant data transfer — on a 2-second poll interval with 100 events/second, this reduces transfer from 200 events per poll to just the new ones since last poll.

**XPC type constraint:** All complex types cross the XPC boundary as JSON-encoded `Data` because NSXPCInterface only supports `@objc`-compatible types. Protocols use `Data`, `String`, `Bool`, `Int`, and `[String:Any]` exclusively.

**Connection security:** The endpoint extension verifies the code signature of the connecting process before accepting XPC connections.

---

## Building

### Requirements

- macOS 15.0+ (Sequoia)
- Xcode 16.0+
- Rust toolchain with `aarch64-apple-darwin` target (for iris-parsers)
- Apple Developer account with system extension entitlements
- Developer ID certificate for code signing (system extensions must be signed)

### Build Steps

```bash
# 1. Build the Rust static library (arm64 only)
cd iris/rust/iris-parsers
./build-rust.sh

# 2. Build the app and all extensions
xcodebuild -scheme Iris -configuration Debug -arch arm64 ONLY_ACTIVE_ARCH=YES build
```

The Rust library compiles arm64 only. **You must pass `-arch arm64` to xcodebuild** or the linker will fail looking for x86_64 symbols.

### Installation

1. Build and run from Xcode (or `xcodebuild` + manual launch)
2. macOS will prompt to allow system extensions — approve in System Preferences → Privacy & Security
3. Open Iris Settings → Enable each extension individually:
   - **Endpoint Security** — requires Full Disk Access
   - **Network Proxy** — requires Network Extension approval
   - **DNS Proxy** — requires Network Extension approval
4. For TLS MITM: Settings → Install CA Certificate, then trust it in Keychain Access (System keychain, "Always Trust" for SSL)

### Entitlements

| Entitlement | Used By | Purpose |
|-------------|---------|---------|
| `com.apple.developer.endpoint-security.client` | IrisEndpointExtension | Endpoint Security framework subscription |
| `com.apple.developer.networking.networkextension` | IrisProxyExtension, IrisDNSExtension | NETransparentProxyProvider, NEDNSProxyProvider |
| `com.apple.developer.system-extension.install` | Iris.app | Install/uninstall system extensions |
| App Groups | All targets | Shared container for preferences and data |

---

## Project Structure

```
iris/
├── IrisApp/                              Main application entry point
│   ├── IrisApp.swift                     @main App struct, startup sequence
│   ├── CLICommandHandler.swift           DistributedNotificationCenter remote commands
│   ├── RustBatchOps.swift                Rust FFI: batch SHA256, entropy
│   ├── RustDNSParser.swift               Rust FFI: DNS wire format parsing
│   ├── RustMachOParser.swift             Rust FFI: Mach-O binary analysis
│   ├── Components/                       Shared UI components (DetailRow, etc.)
│   ├── Views/                            Home screen, settings views
│   └── Rendering/                        Metal rendering pipeline
│
├── IrisEndpointExtension/                Endpoint Security system extension
│   ├── ESClient.swift                    ES framework client, event dispatch
│   ├── ESClient+ProcessLifecycle.swift   EXEC/FORK/EXIT handling
│   ├── ESClient+SecurityEvents.swift     File/privilege/injection events
│   ├── ESClient+FileEvents.swift         File operation monitoring
│   ├── ESClient+NationStateEvents.swift  Nation-state tradecraft events
│   ├── ESClient+AuthExec.swift           Authorization event handling
│   ├── ESClient+RingBuffer.swift         O(1) bounded event storage
│   ├── ESClient+Muting.swift             Event-specific path muting
│   ├── ESClient+Seeding.swift            Initial process table population
│   ├── ExecPolicy.swift                  Execution policy enforcement
│   ├── MuteSet.swift                     Event-specific mute configuration
│   └── ESXPCService.swift                XPC listener with signature verification
│
├── IrisProxyExtension/                   Transparent proxy system extension
│   ├── AppProxyProvider.swift            NETransparentProxyProvider entry point
│   ├── FlowHandler.swift                 Per-flow routing actor
│   ├── FlowHandler+MITMRelay.swift       HTTPS TLS MITM decryption
│   ├── FlowHandler+HTTPRelay.swift       Plaintext HTTP capture
│   ├── FlowHandler+DNSRelay.swift        DNS-over-HTTPS relay
│   ├── FlowHandler+UDPRelay.swift        UDP datagram relay
│   ├── FlowHandler+Passthrough.swift     Generic TCP/UDP passthrough
│   ├── TLSSession.swift                  SSLCreateContext wrapper
│   ├── TLSSession+Handshake.swift        TLS handshake orchestration
│   ├── TLSSession+IOCallbacks.swift      SSL I/O function implementations
│   ├── TLSSession+ReadWrite.swift        Encrypted read/write operations
│   ├── TLSInterceptor.swift              CA loading, cert generation
│   ├── TLSInterceptor+ASN1.swift         ASN.1 DER encoding
│   ├── TLSInterceptor+CertBuilder.swift  X.509 certificate construction
│   ├── TLSInterceptor+DERParsing.swift   DER format parsing
│   ├── ProxyXPCService.swift             XPC listener + flow/DNS storage
│   ├── DoHClient.swift                   DNS-over-HTTPS client
│   ├── RustHTTPParser.swift              Rust FFI: HTTP request/response parsing
│   ├── SecurityRule.swift                Firewall rule model
│   └── RulePersistence.swift             Rule disk persistence
│
├── Shared/                               Compiled into all targets
│   ├── EndpointXPCProtocol.swift         Endpoint extension XPC protocol
│   ├── ProxyXPCProtocol.swift            Proxy extension XPC protocol
│   ├── DNSXPCProtocol.swift              DNS extension XPC protocol
│   ├── HTTPParser.swift                  HTTP/1.1 parser (multi-file)
│   ├── ProxyCapturedFlow.swift           Network capture data models
│   └── AtomicFlag.swift                  Thread-safe boolean flag
│
├── Packages/
│   ├── IrisSecurity/                     Detection engine (22,652 lines)
│   │   └── Sources/IrisSecurity/
│   │       ├── Engine/                   DetectionEngine, SecurityEventBus,
│   │       │                             CorrelationEngine, FusionEngine,
│   │       │                             AlertStore, ScanSession, ScannerRegistry
│   │       ├── Rules/                    79 detection rules across 8 modules
│   │       │   ├── CredentialTheftRules.swift
│   │       │   ├── PersistenceRules.swift
│   │       │   ├── C2Rules.swift
│   │       │   ├── EvasionRules.swift
│   │       │   ├── InjectionRules.swift
│   │       │   ├── ExfiltrationRules.swift
│   │       │   ├── APTRules.swift
│   │       │   ├── NationStateRules.swift
│   │       │   └── CorrelationRules.swift
│   │       ├── Services/                 57 scanner implementations
│   │       ├── Models/                   ProcessAnomaly, SecurityCheck,
│   │       │                             AnomalyGroup, DylibHijack, etc.
│   │       ├── Intel/                    Threat intelligence databases
│   │       │                             (MalwareC2, MalwarePersistence,
│   │       │                              TargetedPaths for 214+ families)
│   │       └── Views/                    SecurityHubView, ThreatScanView,
│   │                                     15+ security detail views
│   ├── IrisNetwork/                      Network monitoring UI (6,540 lines)
│   ├── IrisProcess/                      Process tree + resources (3,113 lines)
│   ├── IrisDNS/                          DNS monitoring + DoH (2,240 lines)
│   ├── IrisProxy/                        HTTP flow UI (1,692 lines)
│   ├── IrisShared/                       Extension manager (1,337 lines)
│   ├── IrisCertificates/                 Certificate management (1,317 lines)
│   ├── IrisSatellite/                    3D visualization (2,487 lines)
│   ├── IrisDisk/                         Disk usage (991 lines)
│   └── IrisWiFi/                         WiFi monitoring (2,064 lines)
│
├── rust/iris-parsers/                    Rust FFI static library (1,584 lines)
│   ├── src/lib.rs                        FFI entry points
│   ├── src/http.rs                       HTTP parser
│   ├── src/dns.rs                        DNS wire format parser
│   ├── src/macho.rs                      Mach-O parser
│   ├── src/entropy.rs                    Shannon/chi-square/Monte Carlo entropy
│   ├── src/sha256.rs                     Batch hashing
│   └── build-rust.sh                     Build script (arm64 target)
│
├── Tests/                                Swift Testing suites (3,049 lines)
├── scripts/                              CLI tools and build scripts
├── DESIGN_DECISIONS.md                   Architecture decisions log
└── docs/
    ├── ARCHITECTURE.md                   System architecture deep-dive
    ├── DETECTION.md                      Detection engine reference
    └── SCANNERS.md                       Complete scanner reference
```

---

## Further Reading

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Complete system architecture: data flow traces through every extension, XPC protocol definitions, thread safety model, memory management, delta protocol implementation, and extension lifecycle.
- **[docs/DETECTION.md](docs/DETECTION.md)** — Detection engine internals: all 79 simple rules with event types and predicates, all 15 correlation rules with temporal windows, 9 correlation chain patterns, fusion engine scoring formulas, campaign classification logic, and MITRE ATT&CK technique coverage map.
- **[docs/SCANNERS.md](docs/SCANNERS.md)** — Complete scanner reference: every scanner with its enumeration method, specific kernel APIs used, MITRE technique mappings, evidence field descriptions, performance characteristics, and detection examples.
- **[DESIGN_DECISIONS.md](DESIGN_DECISIONS.md)** — Key architecture decisions with rationale: TLS MITM hybrid approach, DNS architecture, NEPacketTunnelProvider cancellation, and evidence-based scoring model.
