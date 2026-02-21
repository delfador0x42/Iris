# Scanner Reference

Complete reference for all 57 security scanners in Iris. Each scanner entry documents what it detects, how it enumerates system state, which MITRE ATT&CK techniques it maps to, what evidence it produces, and performance characteristics.

Scanners are organized by execution tier. All scanners return `[ProcessAnomaly]` — see [Evidence Format](#evidence-format) at the end.

---

## Execution Model

```
SecurityAssessor.scanThreats()
     │
     ├─ Create ScanContext:
     │  ├─ ProcessSnapshot (snapshot of all running processes)
     │  └─ [NetworkConnection] (active network connections from proxy)
     │
     ├─ Phase 1: Fast scanners (17) — parallel via TaskGroup
     │  └─ Wait for all to complete
     │
     ├─ Phase 2: Medium scanners (25) — parallel via TaskGroup
     │  └─ Wait for all to complete
     │
     ├─ Phase 3: Slow scanners (15) — parallel via TaskGroup
     │  └─ Wait for all to complete
     │
     ├─ Collect all [ScannerResult] (scanner ID + [ProcessAnomaly])
     │
     ├─ CorrelationEngine.correlate(results) → [Correlation]
     │
     └─ FusionEngine.fuse(results, correlations, recentAlerts) → FusionResult
```

All scanners within a tier run in parallel. Tiers execute sequentially (fast → medium → slow) to provide progressive results to the UI.

---

## Fast Tier (17 Scanners)

These scanners operate on in-memory data only (ProcessSnapshot, active connections). No filesystem I/O. Typical latency: 2-5ms per scanner.

### LOLBin Detector
**ID:** `lolbin` | **MITRE:** T1059, T1218, T1105 | **Severity:** Medium-High

Detects legitimate macOS binaries being abused for malicious purposes (Living Off the Land). Maintains a database of known LOLBin signatures including:
- **Interpreters:** python, python3, ruby, perl, osascript, swift (used for fileless execution)
- **Download tools:** curl, wget (used for payload delivery)
- **Compilation:** gcc, clang, swiftc (compile-after-delivery)
- **Archive tools:** tar, zip, ditto (staging)
- **System tools:** launchctl, defaults, plutil, PlistBuddy (persistence)
- **Network tools:** nc, ncat, socat (reverse shells, tunnels)

**Enumeration:** Iterates ProcessSnapshot, matches binary paths against LOLBin database, checks execution arguments for suspicious patterns (e.g., `curl | sh`, `python -c`, `osascript -e`).

**Evidence:** `["binary: /usr/bin/curl", "args: -o /tmp/payload https://...", "technique: Download Cradle"]`

---

### Stealth Scanner
**ID:** `stealth` | **MITRE:** T1564.001, T1548.003, T1556.003, T1574.006 | **Severity:** Medium-High

Multi-module scanner covering 9 stealth categories:

| Module | What It Checks |
|--------|---------------|
| Hidden LaunchAgents | LaunchAgents in /Library that are hidden or have suspicious names |
| PAM modules | Custom PAM modules in /usr/lib/pam (authentication backdoors) |
| Sudoers modifications | /etc/sudoers.d/ entries granting NOPASSWD or unusual privileges |
| SUID binaries | Non-standard SUID/SGID binaries outside /usr/bin, /usr/sbin |
| DYLD injection | DYLD_INSERT_LIBRARIES, DYLD_FRAMEWORK_PATH in running processes |
| SSH authorized_keys | Unauthorized keys in ~/.ssh/authorized_keys |
| at(1) jobs | Scheduled jobs via at/atq (uncommon on macOS, often malicious) |
| emond rules | /etc/emond.d/rules/ entries (persistence via event monitor) |
| Quarantine xattr | Downloaded executables missing com.apple.quarantine xattr |

**Enumeration:** Combination of filesystem enumeration, process environment inspection, and extended attribute checks. Each module is a separate method in StealthScanner+*.swift extensions.

---

### Process Integrity
**ID:** `process_integrity` | **MITRE:** T1055, T1036.001, T1574 | **Severity:** Medium-Critical

Checks running processes for code signing violations and memory integrity issues:
- Unsigned processes running from user-writable paths
- Processes with invalid code signatures (tampered after signing)
- Processes whose on-disk binary does not match the running image
- Ad-hoc signed processes in system directories

**Enumeration:** `SecCodeCheckValidity` with `kSecCSCheckAllArchitectures` flag. For deeper checks, uses `mach_vm_region` to inspect memory region protections.

---

### Credential Access Detector
**ID:** `credential_access` | **MITRE:** T1555, T1555.001, T1552.004, T1539 | **Severity:** High-Critical

Detects active credential theft by inspecting running processes for:
- Known credential dumping tool names/paths (mimikatz, pypykatz, LaZagne, chainbreaker)
- Processes accessing Keychain database files
- Processes reading browser credential stores (Login Data, Cookies, key4.db)
- SSH key file access by non-SSH processes
- Cloud credential file access (AWS, Azure, GCP)

**Enumeration:** ProcessSnapshot fields (binary path, arguments, open files) matched against threat intelligence database of 214+ malware families.

---

### DYLD Injection Detector
**ID:** `dyld_env` | **MITRE:** T1574.006, T1562.001 | **Severity:** High

Checks every running process for DYLD environment variable abuse:

| Variable | Risk |
|----------|------|
| DYLD_INSERT_LIBRARIES | Forces library loading into process (primary injection vector) |
| DYLD_FRAMEWORK_PATH | Redirects framework resolution (hijacking) |
| DYLD_LIBRARY_PATH | Redirects library resolution |
| DYLD_FALLBACK_LIBRARY_PATH | Fallback path manipulation |
| DYLD_IMAGE_SUFFIX | Image suffix manipulation (rare but exploitable) |

**Enumeration:** Reads process environment from ProcessSnapshot. On macOS, DYLD variables are stripped by the kernel for protected processes, but non-protected (non-SIP, non-hardened) processes retain them.

---

### Masquerade Detector
**ID:** `masquerade` | **MITRE:** T1036.004, T1036.005 | **Severity:** Medium-High

Detects process name and path spoofing:
- Process named "Finder" but not running from /System/Library/CoreServices/
- Process named "Safari" but not signed by Apple
- Unicode homograph attacks (Cyrillic "а" vs Latin "a" in process names)
- Right-to-left override characters in filenames
- Double extensions (malware.pdf.app)

**Enumeration:** Compares ProcessSnapshot process names against a whitelist of system process name-to-path mappings. Performs Unicode normalization analysis on all process names.

---

### Hidden Process Detector
**ID:** `hidden_process` | **MITRE:** T1014, T1036.004 | **Severity:** Critical

Detects processes that are hidden from standard enumeration tools (ps, Activity Monitor):

**Method:** Uses the `processor_set_tasks()` Mach trap to enumerate all tasks from the kernel's perspective, then compares against the ProcessSnapshot (which uses `proc_listallpids`). Any process visible to the kernel but missing from the standard list is flagged.

This catches rootkit-level process hiding — the technique used by sophisticated macOS malware to remain invisible. Requires `task_for_pid-allow` entitlement.

---

### Memory Scanner
**ID:** `memory` | **MITRE:** T1055, T1620 | **Severity:** High-Critical

Scans process memory for injection artifacts:

**RWX Region Detection:** Uses `mach_vm_region` to enumerate all memory regions in target processes. Regions with simultaneous read+write+execute permissions are flagged — legitimate code is either R+X (code) or R+W (data), never both.

**Mach-O Magic Detection:** Reads the first 4 bytes of suspicious memory regions looking for `MH_MAGIC_64` (0xFEEDFACF), `MH_MAGIC` (0xFEEDFACE), `FAT_MAGIC`, or `FAT_CIGAM`. Mach-O headers in anonymous (non-file-backed) memory indicate reflective code loading.

**__TEXT Integrity:** `TextIntegrityChecker` compares the SHA256 hash of the in-memory `__TEXT` segment against the on-disk binary's `__TEXT` segment. Calculates ASLR slide via `TASK_DYLD_INFO → dyld_all_image_infos → imageLoadAddress`. If hashes differ, the code was patched in memory (process hollowing).

**Thread Count:** Processes with >100 threads are flagged (injection often creates additional threads).

**Enumeration:** `task_for_pid()` → `mach_vm_region()` → `mach_vm_read_overwrite()`. Requires task port access.

---

### Fake Prompt Detector
**ID:** `fake_prompt` | **MITRE:** T1056.002, T1059.002 | **Severity:** High

Detects fake authentication dialogs used to harvest user credentials. Looks for:
- `osascript` displaying dialogs with authentication-related text
- Processes creating windows with titles matching system authentication prompts
- Non-Apple processes using `NSAlert` with password fields

---

### Exploit Tool Detector
**ID:** `exploit_tool` | **MITRE:** T1203, T1588.002 | **Severity:** Critical

Detects known offensive security frameworks and exploitation tools:
- Metasploit (msfconsole, msfvenom, meterpreter)
- Cobalt Strike (beacon, TeamServer artifacts)
- Empire (stagers, listeners)
- Mythic agents (Poseidon, Apfell)
- Sliver C2 agents
- Brute Ratel (badger payloads)

**Enumeration:** Binary path matching + code signing identity checking against threat intel database.

---

### Thread Anomaly Scanner
**ID:** `thread_anomaly` | **MITRE:** T1055 | **Severity:** Medium

Detects processes with anomalous thread counts using `proc_pidinfo(PROC_PIDTASKINFO)`. A process with >100 threads is flagged — this can indicate thread injection, cryptocurrency mining, or other anomalous activity.

---

### Clipboard Scanner
**ID:** `clipboard` | **MITRE:** T1115 | **Severity:** Medium

Inspects the current pasteboard for sensitive data patterns:
- API keys (AWS, Google, Stripe, etc.)
- Private keys (RSA, SSH, PGP headers)
- Password patterns (common password manager formats)
- Credit card numbers (Luhn-valid 16-digit sequences)
- Social Security Numbers, emails, phone numbers

---

### Network Anomaly Detector
**ID:** `network_anomaly` | **MITRE:** T1071, T1573, T1095 | **Severity:** Medium-High

Analyzes network connection patterns for C2 indicators:

**Beaconing Detection:** Calculates coefficient of variation (CoVar) of connection intervals per remote host. Regular intervals (low CoVar) suggest automated C2 checkins rather than human browsing.

**DNS DGA Detection:** Analyzes DNS queries for domain generation algorithm patterns — high entropy domain names, excessive unique subdomain queries, consonant-heavy strings.

**DNS Exfiltration:** Detects unusually long subdomain labels (>30 characters) which may encode exfiltrated data.

**Port Anomalies:** Non-standard ports for known protocols, high-port connections from system processes.

---

### Cloud C2 Detector
**ID:** `cloud_c2` | **MITRE:** T1567.002 | **Severity:** High

Detects command-and-control channels hiding in legitimate cloud services:
- Slack webhook URLs from non-Slack processes
- Discord webhook/bot API calls from non-Discord processes
- Telegram Bot API calls from non-Telegram processes
- Dropbox API calls from non-Dropbox processes
- Google Drive API calls from non-Google processes

---

### Environmental Keying Detector
**ID:** `env_keying` | **MITRE:** T1497, T1497.001 | **Severity:** Medium

Detects malware that checks its execution environment before activating:
- VM detection (VMware tools, VirtualBox Guest Additions, Parallels)
- Sandbox detection (specific file/directory checks)
- Analysis tool detection (Wireshark, tcpdump, dtrace, lldb running)
- Hardware fingerprinting (MAC address, serial number queries)

---

### Process Hollowing Detector
**ID:** `process_hollowing` | **MITRE:** T1055.012 | **Severity:** Critical

Detects processes whose in-memory code differs from their on-disk binary — indicating the process image has been replaced after launch. Uses `TextIntegrityChecker` (see Memory Scanner) to compare `__TEXT` segment hashes with ASLR slide calculation.

---

### Inline Hook Detector
**ID:** `inline_hook` | **MITRE:** T1574.013 | **Severity:** High

Detects ARM64 function trampolines/detours in critical system libraries. Scans the first instructions of loaded libraries for patterns like `LDR X16, [PC+offset]; BR X16` which redirect execution to attacker-controlled code.

**Target libraries:** libsystem_kernel, libsystem_c, libdyld, Security, libsystem_info, libsystem_malloc, libsystem_pthread

**Enumeration:** `TASK_DYLD_INFO → dyld_all_image_infos → enumerate loaded images → mach_vm_read_overwrite first 4KB → scan for LDR+BR patterns`

---

## Medium Tier (25 Scanners)

These scanners read files, parse plists, query SQLite databases, or enumerate system state via filesystem access. Typical latency: 50-500ms per scanner.

### XPC Service Auditor
**ID:** `xpc_services` | **MITRE:** T1574, T1569.001 | **Severity:** Medium-High

Audits XPC service registrations for suspicious definitions: non-Apple services in system directories, services with writable program paths, services running as root without necessity.

### Mach Service Auditor
**ID:** `mach_services` | **MITRE:** T1559.001 | **Severity:** Medium

Inspects Mach bootstrap namespace for suspicious service registrations that could intercept legitimate IPC.

### Kext Anomaly Detector
**ID:** `kext` | **MITRE:** T1547.006, T1014 | **Severity:** High-Critical

Enumerates loaded kernel extensions and compares against IPSW baseline (674 known-good kexts). Unsigned kexts, kexts not in the baseline, and kexts with invalid signatures are flagged.

### Authorization DB Monitor
**ID:** `auth_db` | **MITRE:** T1548.004, T1556 | **Severity:** High

Parses `/var/db/auth.db` for modified authorization rules. Detects custom rules that bypass password requirements, rules granting admin to non-admin users, and rules targeting sensitive rights (system.privilege.admin, com.apple.SoftwareUpdate).

### Persistence Scanner
**ID:** `persistence` | **MITRE:** T1547, T1543, T1546, T1176 | **Severity:** Medium-High

Comprehensive persistence mechanism enumeration covering 13 categories:

| Category | Locations Scanned |
|----------|------------------|
| LaunchAgents (user) | ~/Library/LaunchAgents/*.plist |
| LaunchAgents (system) | /Library/LaunchAgents/*.plist |
| LaunchDaemons | /Library/LaunchDaemons/*.plist |
| Login Items | BTM registered items + LSSharedFileList |
| Cron Jobs | /usr/lib/cron/tabs/*, /var/at/tabs/* |
| Kernel Extensions | /Library/Extensions/*.kext |
| System Extensions | /Library/SystemExtensions/* |
| Browser Extensions | Chrome/Firefox/Safari extension directories |
| Authorization Plugins | /Library/Security/SecurityAgentPlugins/*.bundle |
| Login/Logout Hooks | defaults read loginwindow LoginHook/LogoutHook |
| Startup Scripts | /etc/rc.d/*, /Library/StartupItems/* |
| Shell Configs | ~/.zshrc, ~/.bashrc, ~/.bash_profile, ~/.profile, /etc/zshenv |
| Periodic Scripts | /etc/periodic/daily/*, weekly/*, monthly/* |

Each item is checked for: code signing status, path writability, plist content (program arguments, run conditions), and comparison against IPSW baseline.

### Event Tap Scanner
**ID:** `event_taps` | **MITRE:** T1056.001 | **Severity:** High

Detects keylogger-style event taps via `CGGetEventTapList()`. Returns all active event taps with their tapping process, event mask, and tap type. Keyboard taps from non-Apple, non-accessibility processes are flagged as suspicious.

### TCC Monitor
**ID:** `tcc` | **MITRE:** T1005 | **Severity:** High

Queries TCC.db (Transparency, Consent, and Control) for suspicious privacy grants. Checks for:
- Camera access by non-camera apps
- Microphone access by non-communication apps
- Full Disk Access granted to unknown processes
- Accessibility access (can control UI, read keystrokes)
- Screen recording permission

Uses `RustBatchOps` for SHA256 verification of client binaries.

### Ransomware Detector
**ID:** `ransomware` | **MITRE:** T1486 | **Severity:** Critical

Monitors Endpoint Security write events for ransomware indicators:
- High-entropy file creation (entropy > 7.5 on Shannon scale)
- Mass file modification (>10 files in 60 seconds by same process)
- Known ransomware file extensions (.encrypted, .locked, .ransom, etc.)
- Ransom note creation (README.txt, DECRYPT.txt patterns)

### System Integrity Scanner
**ID:** `system_integrity` | **MITRE:** T1553.006, T1014, T1542 | **Severity:** Critical

Checks macOS security subsystem state:
- SIP status (csrutil status)
- AMFI status (amfi_get_out_of_my_way boot-arg)
- Secure kernel boot (kern.secure_kernel sysctl)
- Boot arguments (boot-args NVRAM variable)
- FileVault status

### Network Config Auditor
**ID:** `network_config` | **MITRE:** T1565.001, T1557 | **Severity:** Medium-High

Inspects network configuration for manipulation:
- DNS resolver configuration (/etc/resolv.conf, scutil --dns)
- Routing table anomalies (unexpected default routes)
- Proxy settings (HTTP/HTTPS/SOCKS proxy configured)
- /etc/hosts file modifications

### Staging Detector
**ID:** `staging` | **MITRE:** T1074.001, T1555 | **Severity:** High

Scans temporary directories (/tmp, /var/tmp, ~/Library/Caches) for staged files matching 214+ known malware family patterns. Targets include:

| Category | Paths Monitored |
|----------|----------------|
| Browser credentials | Chrome Login Data, Firefox logins.json, Safari cookies |
| Crypto wallets | Electrum, Exodus, MetaMask, Coinbase, Atomic |
| SSH keys | ~/.ssh/id_*, authorized_keys, known_hosts |
| Cloud credentials | ~/.aws/credentials, ~/.azure, ~/.gcloud, ~/.kube, ~/.docker |
| Keychain | ~/Library/Keychains/*.keychain-db |
| TCC database | ~/Library/Application Support/com.apple.TCC/TCC.db |

### USB Device Scanner
**ID:** `usb` | **MITRE:** T1200, T1091 | **Severity:** Medium-High

Enumerates connected USB devices via IOKit and checks for:
- USB Billboard devices (may indicate BadUSB)
- Devices claiming to be HID (keyboard/mouse) with unusual vendor/product IDs
- Known attack tool USB identifiers (Rubber Ducky, O.MG Cable, Bash Bunny)
- USB mass storage devices (potential exfiltration vector)

### Remaining Medium Scanners

| ID | Scanner | Key Detection | Enumeration |
|----|---------|--------------|-------------|
| `xattr` | Xattr Abuse | Missing quarantine on downloads, resource fork abuse | Extended attribute scan |
| `hidden_files` | Hidden Files | Hidden files in critical paths | Dot-file enumeration |
| `log_integrity` | Log Integrity | Tampered/deleted system logs | Log file metadata analysis |
| `screen_capture` | Screen Capture | Unauthorized screen recording | CGDisplayStream + process check |
| `covert_channel` | Covert Channel | Timing channels, HTTP header channels | Traffic pattern analysis |
| `firewall` | Firewall Auditor | Bypass rules, port forwarding | pfctl rule inspection |
| `mach_port` | Mach Port Scanner | Malicious IPC registrations | Bootstrap namespace |
| `script_backdoor` | Script Backdoors | Backdoored shell configs | Shell script pattern matching |
| `download_provenance` | Download Provenance | Suspicious download sources | Metadata + URL analysis |
| `crash_reports` | Crash Reports | Exploitation artifacts | Crash log parsing |
| `dns_tunnel` | DNS Tunneling | DNS exfiltration channels | Query entropy analysis |
| `persistence_monitor` | Persistence Monitor | Changes since baseline | SHA256 snapshot diff |
| `timestomp` | Timestomp Detector | File time manipulation | POSIX timestamp checks |

---

## Slow Tier (15 Scanners)

These scanners perform code signing verification, deep binary parsing, or network-dependent checks. Typical latency: >500ms per scanner.

### Binary Integrity Scanner
**ID:** `binary_integrity` | **MITRE:** T1036, T1553.002 | **Severity:** High-Critical

Performs full code signature verification on running processes:
- `SecStaticCodeCreateWithPath` + `SecStaticCodeCheckValidityWithErrors`
- Checks for ad-hoc signatures (no identity, not notarized)
- Validates signature chain to Apple root or known developer
- Inspects entitlements for dangerous capabilities:
  - `com.apple.security.get-task-allow` (debugger attachment)
  - `com.apple.security.cs.disable-library-validation` (load unsigned dylibs)
  - `com.apple.private.*` (private API access)
  - `task_for_pid-allow` (inspect other processes)

### Dylib Hijack Scanner
**ID:** `dylib_hijack` | **MITRE:** T1574.004, T1574.001 | **Severity:** High

Analyzes Mach-O load commands for hijacking vulnerabilities:
- LC_LOAD_DYLIB paths that don't exist on disk (attacker can place a dylib there)
- LC_RPATH entries pointing to writable directories
- @rpath resolution that could be redirected
- Weak dylib references that fail silently (attacker substitution)

Filters out known-benign missing dylibs (development frameworks, optional dependencies).

### Supply Chain Auditor
**ID:** `supply_chain` | **MITRE:** T1195, T1195.001, T1195.002 | **Severity:** Medium-High

Audits installed packages from:
- **npm:** Checks node_modules for known-malicious packages, typosquatting, preinstall/postinstall scripts
- **pip:** Checks installed Python packages against known-vulnerable database
- **Homebrew:** Checks installed formulae for tampering (formula hash mismatch)

### Phantom Dylib Detector
**ID:** `phantom_dylib` | **MITRE:** T1574.001, T1574.002 | **Severity:** High

Scans running process Mach-O headers for LC_LOAD_DYLIB entries that reference libraries not present on the filesystem. An attacker who places a dylib at the missing path gets code execution in the target process.

### Remaining Slow Scanners

| ID | Scanner | Key Detection | Method |
|----|---------|--------------|--------|
| `certificate` | Certificate Auditor | Malicious CAs in trust store | Keychain enumeration |
| `browser_ext` | Browser Extensions | Malicious extensions | Extension dir + manifest parse |
| `entitlement` | Entitlement Scanner | Dangerous entitlements on running processes | SecCodeCopySigningInformation |
| `security_evasion` | Security Tool Evasion | Anti-analysis, debugger detection | Binary + behavioral analysis |
| `vm_container` | VM/Container Detector | VMs, Docker, hypervisors | Hardware fingerprint + runtime |
| `boot_security` | Boot Security | Secure boot, NVRAM, firmware, SEP | bputil + IOKit NVRAM |
| `kernel_integrity` | Kernel Integrity | MACF rootkits, kext policy violations | MACF sysctl + trust caches |
| `dyld_cache` | Dyld Cache | Corrupted shared cache | Cache hash verification |
| `iokit_driver` | IOKit Drivers | Malicious drivers, firmware implants | IOKit enum + codesign |
| `app_audit` | Application Auditor | Trojanized apps, fake system apps | Bundle + signing analysis |
| `browser_history` | Browser History | C2 artifacts in browsing history | SQLite (Chrome, Safari, Firefox) |

---

## Evidence Format

Every scanner returns `[ProcessAnomaly]`:

```swift
struct ProcessAnomaly: Identifiable, Sendable, Codable, Equatable {
    let id: UUID
    let pid: pid_t                    // 0 if not process-specific
    let processName: String
    let processPath: String
    let parentPID: pid_t
    let parentName: String
    let technique: String             // Human-readable: "Process Hollowing"
    let description: String           // Detailed: "Chrome (PID 1234) __TEXT modified"
    let severity: AnomalySeverity     // .critical, .high, .medium, .low
    let mitreID: String?              // "T1055.012"
    let scannerId: String             // "memory" — matches ScannerEntry.id
    let enumMethod: String            // "task_for_pid + mach_vm_read, SHA256 compare"
    let evidence: [String]            // ["pid: 1234", "disk_hash: a1b2c3", "mem_hash: d4e5f6"]
}
```

**`scannerId`** matches the `id` field in `ScannerRegistry+Entries.swift`. This links findings back to their scanner for correlation and fusion.

**`enumMethod`** describes how the data was collected — useful for understanding what kernel APIs or system tools were used, which helps assess the reliability and scope of the finding.

**`evidence`** is an array of key-value strings providing the raw data that led to the finding. Format: `"key: value"`. Common keys:
- `pid` — Process ID
- `path` — File or binary path
- `binary` — Binary name
- `signing` — Code signing status
- `entropy` — Shannon entropy value
- `hash` — SHA256 hash
- `technique` — Specific sub-technique name
- `connections` — Connection count
- `remote` — Remote address

### Severity Levels

| Level | Score Weight | Meaning |
|-------|-------------|---------|
| Critical | 1.0 | Confirmed compromise or active exploitation |
| High | 0.7 | Strong indicator of compromise, requires immediate investigation |
| Medium | 0.4 | Suspicious activity, may be benign, should be reviewed |
| Low | 0.1 | Informational, potential indicator when combined with other findings |

---

## Scanner Registration

All scanners are registered in `ScannerRegistry+Entries.swift`:

```swift
extension ScannerEntry {
    static let all: [ScannerEntry] = fast + medium + slow

    static let fast: [ScannerEntry] = [
        ScannerEntry(id: "lolbin", name: "LOLBin Detector", tier: .fast) { ctx in
            await LOLBinDetector.shared.scan(snapshot: ctx.snapshot)
        },
        // ... 16 more fast scanners
    ]

    static let medium: [ScannerEntry] = [
        // ... 25 medium scanners
    ]

    static let slow: [ScannerEntry] = [
        // ... 15 slow scanners
    ]
}
```

To add a new scanner:
1. Create the scanner implementation (conform to singleton pattern with `static let shared`)
2. Add a `ScannerEntry` to the appropriate tier array in `ScannerRegistry+Entries.swift`
3. Add the scanner ID to `FusionEngine.scannerMap` to map it to a kill chain stage
4. Return `[ProcessAnomaly]` from the scan method with proper `scannerId`, `mitreID`, `enumMethod`, and `evidence`
