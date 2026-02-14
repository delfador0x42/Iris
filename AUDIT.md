# Iris Security Audit Findings

All bug findings from 4 audit rounds. Organized by component. Status: OPEN / FIXED / WONTFIX.
See also: `../iris-research/THREAT_MODEL.md`, `SCANNER_INVENTORY.md`, `DETECTION_GAPS.md`.

## IrisSecurity Package

### Critical: Package Not In Xcode Project
SecurityAssessor.assess() only calls SystemSecurityChecks.runAll() (8 checks). 14 of 18 scanners ARE wired to Views but package has ZERO entries in pbxproj. **STATUS: OPEN**

**Truly orphaned scanners (4):** RansomwareDetector, EntropyAnalyzer, AVMonitor, PersistenceMonitor
**Wired to views but unreachable:** All 14 others (package not in Xcode project)

### Scanner Summary

| Scanner | MITRE | Effectiveness | Status |
|---------|-------|--------------|--------|
| SystemSecurityChecks (8) | T1562, T1486, T1553, T1021, T1078 | ACTIVE | OK |
| DyldEnvDetector | T1574 | 85% | Minor gaps |
| DylibHijackScanner + MachOParser | T1574.001, T1574.004 | 50% | Fat binary bug |
| AuthorizationDBMonitor | T1547.002 | 50% | 10/1000+ rights |
| FileSystemBaseline (FIM) | T1565, T1036 | 40-50% | S4, depth/symlink |
| LOLBinDetector | T1059, T1218, T1555, T1005 | 35-40% | FIXED: 44 LOLBins, 8-level ancestry |
| EventTapScanner | T1056.001 | 30% | FIXED: 30+ benign entries |
| ProcessIntegrityChecker | T1055, T1574.006 | 25-30% | proc_regionfilename <1% |
| CredentialAccessDetector | T1552, T1555 | 20% | Browser cookie FPs |
| StealthScanner (9 techniques) | T1564, T1546, T1556, T1548 | 20% | Emond dead code |
| NetworkAnomalyDetector | T1571, T1573, T1071 | 60% | FIXED: SecurityStore data + lsof fallback |
| TCCMonitor | T1557, T1005 | 50% | FIXED: FDA+sqlite3 CLI, deny→allow detection |
| SupplyChainAuditor | T1195 | 40% | Xcode plugin obsolete |
| XPCServiceAuditor | T1559 | 40% | No known-good whitelist |
| KextAnomalyDetector | T1547.006 | 40% | FIXED: macOS malware names |
| PersistenceScanner (13 types) | T1543, T1547, T1053, T1546 | 40% | No content analysis |
| PersistenceMonitor | T1543, T1547 | 10% | BROKEN: no ES wiring |
| RansomwareDetector + EntropyAnalyzer | T1486 | N/A | Orphaned |
| AVMonitor | T1123, T1125 | N/A | Orphaned |
| SigningVerifier (shared) | — | 50% | FIXED: Team ID + hardened runtime |

### Scanner Bugs

**BROKEN (must rewrite):**
1. **TCCMonitor** — SIP prevents TCC.db reads without FDA. STATUS: FIXED (SIP disabled, FDA granted, timestamp bug fixed, deny→allow detection added)
2. **NetworkAnomalyDetector** — macOS netstat has no PIDs. STATUS: FIXED (uses SecurityStore data from NEFilter, lsof fallback retained)
3. **PersistenceMonitor** — Zero ES integration, polling-only. **Fix: Wire to ESClient events.** STATUS: OPEN

**SIGNIFICANT (fix in place):**
4. **EventTapScanner** — flagsMask vs eventsOfInterest bug, benign list short. STATUS: FIXED (Session B2)
5. **LOLBinDetector** — 1-level ancestry, 33 entries. STATUS: FIXED (Session B2: 8-level, 44 entries)
6. **ProcessIntegrityChecker** — proc_regionfilename scans <1%. **Fix: task_info(TASK_DYLD_INFO).** STATUS: OPEN
7. **KextAnomalyDetector** — Linux rootkit names. STATUS: FIXED (Session B2: macOS names)
8. **StealthScanner** — Emond dead (10.11+), SUID only 5 dirs. STATUS: OPEN
9. **CredentialAccessDetector** — Browser cookie FPs, bash-wrapped invisible. STATUS: OPEN
10. **SupplyChainAuditor** — No PyPI reference set, Xcode plugin obsolete. STATUS: OPEN
11. **SigningVerifier** — No entitlements/Team ID/revocation. STATUS: FIXED (Session B2)
12. **FileSystemBaseline** — 50MB limit, no symlink, no depth guard. STATUS: OPEN
13. **PersistenceScanner+Shell** — Detects files not content. STATUS: OPEN

**CODE QUALITY:**
- ProcessEnumeration shared helper extracted. STATUS: FIXED (Session B2)
- 3+ files exceed 300-line limit. STATUS: OPEN
- Zero tests for IrisSecurity. STATUS: OPEN

### Scanner Logic Bugs

**S1.** CredentialAccessDetector wrong vnode struct access. STATUS: OPEN
**S2.** XPCServiceAuditor shell wrapper misidentification. STATUS: OPEN
**S3.** AuthorizationDBMonitor string-contains "allow" matches "disallow". STATUS: OPEN
**S4.** FileSystemBaseline no depth guard. STATUS: OPEN
**S5.** DyldEnvDetector collects all env vars before filtering. STATUS: OPEN (minor)

---

## View Layer (IrisSecurity/Views/)

**V1.** No task cancellation in any security view — resource leaks on navigation. STATUS: OPEN
**V2.** No error handling on scanner calls — stuck UI on failure. STATUS: OPEN
**V3.** ThreatScanView count/filter mismatch — badge vs list disagree. STATUS: OPEN
**V4.** ProcessAnomaly timestamp skew — Date() default spreads timestamps. STATUS: OPEN

---

## Extension Layer

### TLS/Proxy Extension

**E1.** TLSSession use-after-free — retainedRef released while callbacks may fire. STATUS: OPEN
**E2.** TLSSession+IOCallbacks write hang — semaphore blocks SSL queue 10s. STATUS: OPEN
**E3.** UDP flow reader never stops — recursive readLoop after timeout. STATUS: FIXED (Session B1)
**E4.** DNS TCP frame parsing no bounds check. STATUS: OPEN
**E5.** DNS UDP datagram no minimum size check (12 bytes). STATUS: OPEN
**E6.** ExtensionDoHClient unencrypted fallback to 8.8.8.8:53. STATUS: OPEN

**P1.** SSLWrite infinite loop on errSSLWouldBlock. STATUS: FIXED (Session B1)
**P2.** Double-resume in waitForData continuation. STATUS: OPEN
**P3.** close() not thread-safe — SSLClose without lock. STATUS: FIXED (Session B1)
**P4.** TLS handshake never times out. STATUS: FIXED (Session B1)
**P5.** startFlowReader called multiple times. STATUS: OPEN
**P6.** Certificate cache eviction not LRU. STATUS: FIXED (Session B1)
**P7.** Keychain pollution from createIdentity. STATUS: OPEN
**P8.** buildInteger doesn't handle negative/high-bit values. STATUS: OPEN
**P9.** No IP SAN support. STATUS: FIXED (Session B1)
**P10.** UTCTime only valid until 2049. STATUS: OPEN (won't matter for 23 years)
**P11.** extractSubjectName no bounds-check DER parsing. STATUS: FIXED (Session B1)
**P12.** Certificate cache lookup/insert race. STATUS: FIXED (Session B1)
**P13.** Port 443 hard-coded as only HTTPS. STATUS: OPEN
**P14.** UDP flow relay fundamentally broken. STATUS: OPEN
**P15.** Only first HTTP request/response captured per connection. STATUS: FIXED (message boundary tracking in RelayState)
**P16.** RelayState request buffer grows without bound. STATUS: FIXED (Session B1)
**P17.** receiveFromServer timeout double-resume. STATUS: OPEN
**P18.** Passthrough relay doesn't close flow on server disconnect. STATUS: OPEN
**P19.** HTTP request smuggling via duplicate Content-Length. STATUS: FIXED (Session B1)
**P20.** Chunked encoding size overflow. STATUS: OPEN
**P21.** getFlows serializes ALL flows on every poll. STATUS: OPEN

**PROXY1.** NSLock across async suspension points. STATUS: OPEN
**PROXY2.** No HTTP/2 or HTTP/3 detection. STATUS: OPEN
**PROXY3.** No rate limiting on flow creation. STATUS: OPEN
**PROXY4.** Flow leak on unhandled exceptions. STATUS: OPEN
**PROXY5.** Keychain operations not atomic. STATUS: OPEN
**PROXY6.** Only first request/response captured (=P15). STATUS: FIXED (message boundary tracking)
**PROXY7.** Content-Length body extraction takes all remaining data. STATUS: OPEN

### Endpoint Security Extension

**ES1.** ES entirely stubbed — zero es_subscribe calls. STATUS: PARTIALLY FIXED (ESClient rewritten with real ES)
**ES2.** ESProcessInfo vs ProcessInfo model mismatch. STATUS: OPEN
**ES3.** ISO8601 date encoding/decoding mismatch. STATUS: OPEN
**ES4.** No es_mute_process for own PID. STATUS: OPEN
**ES5.** No es_retain_message for async processing. STATUS: OPEN
**ES6.** Self-capture in ES callback. STATUS: OPEN
**ES7.** XPC continuation can hang forever. STATUS: OPEN
**ES8.** Missing critical ES events (OPEN, WRITE, RENAME, etc.). STATUS: OPEN
**ES9.** FileManager.fileExists per-process in computed property (perf). STATUS: OPEN
**ES10.** No event batching/rate limiting. STATUS: OPEN
**ES11.** No XPC reconnection logic. STATUS: OPEN
**ES12.** No app-side code signing verification for ES XPC. STATUS: OPEN
**ES13.** Short-lived processes invisible (polling limitation). STATUS: OPEN
**ES14.** ProcessStore not shared singleton in some views. STATUS: OPEN

### DNS Extension

**D1.** TCP buffer unbounded growth — OOM. STATUS: FIXED (Session B1)
**D2.** skipDNSName missing bounds check. STATUS: FIXED (Session B1)
**D3.** DNS compression pointer single byte (should be 14-bit). STATUS: FIXED (Session B1)
**D4.** SERVFAIL response echoes raw query bytes. STATUS: FIXED (Session B1)
**D5.** No maximum DNS response size check. STATUS: FIXED (Session B1)
**DNS1.** No RDATA format validation on responses. STATUS: OPEN
**DNS2.** Process name spoofing via bundle ID last component. STATUS: OPEN
**DNS3.** No query rate limiting. STATUS: OPEN
**DNS4.** TCP buffer no size limit. STATUS: OPEN
**DNS5.** ExtensionDoHClient arbitrary server if app compromised. STATUS: OPEN

---

## XPC Store Layer

**X1.** Timer not stopped on connection invalidation. STATUS: FIXED (Session B1)
**X2.** No reconnection on extension restart. STATUS: OPEN
**X3.** XPC handlers set after resume. STATUS: OPEN
**X4.** RelayState TOCTOU in MITM relay. STATUS: OPEN

---

## Architectural Issues

**A1.** SecurityAssessor only runs 8 of 30 checks. STATUS: OPEN
**A2.** PersistenceScanner+System marks ALL cron jobs suspicious. STATUS: FIXED (Session B1)

---

## Memory Safety

**M1.** proc_fdinfo buffer misalignment — heap overflow. STATUS: FIXED (Session B1)
**M2.** MachOParser integer truncation on 32-bit. STATUS: OPEN
**M3.** Unbounded sysctl allocation — memory bomb. STATUS: FIXED (Session B1)

---

## Concurrency

**C1.** ProxyXPCService.interceptionEnabled data race. STATUS: FIXED (Session B1)
**C2.** capturedFlows.count read without lock. STATUS: FIXED (Session B1)
**C3.** TLSSession.isClosed unguarded flag. STATUS: OPEN

---

## Network Filter

**N1.** Rule port defaults to wildcard on parse failure. STATUS: OPEN
**N2.** Single eviction on maxConnections overflow. STATUS: OPEN

---

## IrisNetwork — Enrichment & Firewall

**NET1.** IPv4-mapped IPv6 not detected as private. STATUS: OPEN
**NET2.** GreyNoise rate limit race condition. STATUS: OPEN
**NET3.** Enrichment data not persisted — lost on restart. STATUS: OPEN
**NET4.** Shodan URL injection via unvalidated remoteAddress. STATUS: OPEN
**NET5.** batchEnrich() concurrent tasks exceed rate limits. STATUS: OPEN
**NET6.** BoundedCache TTL uses `>` not `>=`. STATUS: OPEN
**NET7.** Sensitive headers copied to clipboard unredacted. STATUS: FIXED (Session B1)
**NET8.** SecurityRule hostname matching logic fragile. STATUS: OPEN
**NET9.** Port validation silent failure. STATUS: OPEN
**NET10.** No enrichment deduplication. STATUS: OPEN
**NET11.** No threat correlation / composite scoring. STATUS: OPEN (improvement)
**NET12.** IPv6 sorting lexicographic not numeric. STATUS: OPEN
**NET13.** No XPC data integrity signature. STATUS: OPEN (improvement)
**NET14.** No XPC call timeout. STATUS: OPEN
**NET16.** staleTimeout cleanup doesn't stop flow forwarding. STATUS: OPEN

---

## IrisProcess

**PROC1.** Off-by-one in KERN_PROCARGS2 parsing. STATUS: OPEN
**PROC2.** TOCTOU race in deletedBinary detection. STATUS: OPEN
**PROC3.** Code signing uses string matching, not crypto. STATUS: OPEN
**PROC4.** Arbitrary argc < 256 cutoff. STATUS: OPEN
**PROC5.** Unsafe memory rebound without alignment check. STATUS: OPEN
**PROC6.** Command injection risk in ManPageStore. STATUS: OPEN
**PROC7.** File existence in computed suspicionReasons (perf). STATUS: OPEN
**PROC8.** No process baseline / drift detection. STATUS: OPEN (improvement)

---

## IrisCertificates

**CERT1.** No IP address SAN support. STATUS: FIXED (Session B1)
**CERT2.** No keyUsage extension on leaf certificates. STATUS: FIXED (Session B1)
**CERT3.** UTCTime will break in 2050. STATUS: OPEN (not urgent)
**CERT4.** CA certificate lacks pathLenConstraint. STATUS: OPEN
**CERT5.** buildSubjectPublicKeyInfo double-wraps RSA key. STATUS: OPEN
**CERT6.** createIdentity leaks keychain items on crash. STATUS: OPEN
**CERT7.** Race condition in getCertificate. STATUS: OPEN
**CERT8.** SecRandomCopyBytes return value ignored. STATUS: OPEN
**CERT9.** Two independent ASN.1 implementations (tech debt). STATUS: OPEN
**CERT10.** Forced type cast crash on keychain lookup. STATUS: OPEN
**CERT11.** Unmanaged<CFError> takeRetainedValue memory leak. STATUS: OPEN
**CERT12.** DER parseLength off-by-one. STATUS: FIXED (Session B1)
**CERT13.** No cert expiration validation in CertificateCache. STATUS: OPEN
**CERT14.** Serial number entropy — SecRandomCopyBytes unchecked. STATUS: OPEN
**CERT15.** Typo: `storageFailer` in error enum. STATUS: FIXED (Session B1)

---

## IrisShared + Shared/

**SHARED1.** Integer overflow in chunked encoding UInt→Int cast. STATUS: FIXED (Session B1)
**SHARED2.** Content-Length: Int.max causes infinite buffering. STATUS: FIXED (Session B1)
**SHARED3.** XPC ping continuation double-resume crash. STATUS: FIXED (Session B1)
**SHARED4.** No rate limiting on XPC protocol calls. STATUS: OPEN
**SHARED5.** Missing connection invalidation on rejected XPC. STATUS: OPEN

---

## IrisWiFi

**WIFI1.** Command injection via airport preference setting — no key allowlist. STATUS: OPEN
**WIFI2.** system_profiler subprocess race + no timeout. STATUS: OPEN
**WIFI3.** WiFi power state TOCTOU. STATUS: OPEN
**WIFI4.** Airport output parsing loses values with `=`. STATUS: OPEN

---

## IrisDisk

**DISK1.** Symlink traversal — follows symlinks recursively. STATUS: FIXED (Session B1)
**DISK2.** No volume crossing check. STATUS: OPEN
**DISK3.** Cache stored in world-readable directory. STATUS: OPEN

---

## System Extensions — Cross-Cutting

**EXT1.** All XPC uses empty SecCSFlags — no strict validation. STATUS: OPEN
**EXT2.** No mutual XPC authentication (extension → app). STATUS: OPEN
**EXT3.** Rule matching allows unsigned binary to match signed rule. STATUS: OPEN
**EXT4.** Relay timeout only closes write half. STATUS: OPEN

---

## Entitlements

**ENT1.** Network extension has 7 NE entitlements, needs 1. STATUS: OPEN
**ENT2.** Other extension entitlements not yet audited. STATUS: OPEN

---

## App Layer — UI & Lifecycle

**APP1.** No crash recovery / state persistence. STATUS: OPEN
**APP2.** Disable filter toggle with zero confirmation. STATUS: OPEN
**APP3.** Uninstall extension with zero confirmation. STATUS: OPEN
**APP4.** No tamper detection / self-integrity checking. STATUS: OPEN
**APP5.** No app lifecycle authentication. STATUS: OPEN
**APP6.** API key stored in plaintext UserDefaults. STATUS: OPEN
**APP7.** No continuous monitoring for extension failures. STATUS: OPEN
**APP8.** No warning when extensions fail to install. STATUS: OPEN
**APP9.** Metal shader no bounds check on button index. STATUS: OPEN
**APP10.** Zero test coverage for app layer. STATUS: OPEN

---

## IrisSatellite

**SAT1.** Shader compilation failure has no fallback. STATUS: OPEN
**SAT2.** Frame semaphore value not validated. STATUS: OPEN

---

## False Positives (confirmed NOT bugs)

- **FP1.** ObjectIdentifier(flow) use-after-free — NEFilterFlow retained by framework. Not a bug.
- **FP2.** peekInboundBytes = Int.max — standard Apple pattern. Not a bug.
- **FP3.** ConnectionTracker lost updates — guarded by connectionsLock. Not a bug.
- **FP4.** audit_token_to_pid >= 24 bound — correct minimum. Not a bug.
- **FP5.** TLS verify_block calling complete(true) — intentional MITM behavior. Not a bug.

---

## Top 10 Attack/Parry Pairs

| # | Operation | MITRE | Parry | Status |
|---|-----------|-------|-------|--------|
| 1 | PHANTOM THREAD — DNS Tunneling | T1071.004 | DNSThreatAnalyzer (entropy/frequency) | Data collected, analyzer not built |
| 2 | GOLDEN BRIDGE — Supply Chain + Shell | T1195, T1059.004 | SupplyChainAuditor + ShellConfigAnalyzer | Scanners exist, no content analysis |
| 3 | DEEP CURRENT — Encrypted C2 | T1573.002, T1571 | NetworkAnomalyDetector beaconing | FIXED: wired to SecurityStore data |
| 4 | SILK ROAD — LOLBin Chain | T1059.002, T1218 | LOLBinDetector | FIXED: 44 LOLBins, 8-level ancestry |
| 5 | CRYSTAL PALACE — Auth Plugin | T1547.002 | PersistenceScanner | Partial: directory scan, no auth.db |
| 6 | SHADOW PUPPET — FinderSync Keylogger | T1056.001, T1547.015 | EventTapScanner | Tap detection works, no extension enum |
| 7 | QUICKSILVER — Chunked HTTP Exfil | T1041, T1030 | NetworkConnection bytes | Data available, analysis not built |
| 8 | ROOTKIT HOTEL — Kext Persistence | T1547.006 | PersistenceScanner + FIM | File detection works, runtime limited |
| 9 | WHISPER NET — ICMP Covert Channel | T1095 | Architectural gap | NEFilter sees TCP/UDP only |
| 10 | GLASS HOUSE — TCC Bypass | T1005, T1552.001 | TCCMonitor | FIXED: reads both TCC.db, deny→allow detection |

---

## Priority Fix Order

1. **P0**: Add IrisSecurity to pbxproj + wire HomeView → SecurityHubView
2. ~~**P0**: Rewrite NetworkAnomalyDetector~~ STATUS: FIXED (SecurityStore data + lsof fallback)
3. ~~**P0**: Rewrite TCCMonitor~~ STATUS: FIXED (FDA+sqlite3, timestamp fix, deny→allow detection)
4. **P0**: Fix ProcessIntegrityChecker (task_info TASK_DYLD_INFO)
5. **P1**: Add shell config content analysis to PersistenceScanner
6. **P1**: Wire PersistenceMonitor to ES events
7. **P2**: Fix StealthScanner (remove emond, expand SUID dirs)
8. **P2**: Fix CredentialAccessDetector (filter browser cookie FPs)
9. **P2**: Fix SupplyChainAuditor (remove obsolete Xcode plugin check)

---

## Instance Work Log

### Instance A: Evidence-Based Scoring (COMPLETE)
Created Evidence.swift, BaselineService.swift, baseline-25C56.json. Refactored PersistenceItem + all 6 scanner extensions with evidence accumulation. Backward compatible.

### Instance B: Bug Fixes + Scanner Quality (COMPLETE)
**Session 1:** Fixed SHARED1/2/3, CERT12/15/2, E3, P1/3/4/6/9/11/12/16/19, M1/M3, C1/C2, NET7, DISK1, X1, D1-5, A2. Wired 4 orphaned scanners. SecurityHubView 6→11 modules. ThreatScanView 11→15 phases.
**Session 2:** Fixed EventTapScanner (30+ benign), LOLBinDetector (8-level/44 LOLBins), KextAnomalyDetector (macOS names), SigningVerifier (Team ID + hardened runtime). Extracted ProcessEnumeration shared helper.
