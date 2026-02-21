import Foundation

/// All registered scanners, categorized by execution tier.
/// Fast scanners use only the ProcessSnapshot (in-memory).
/// Medium scanners read files or parse plists.
/// Slow scanners shell out to codesign, docker, sqlite3, etc.
extension ScannerEntry {

  public static let all: [ScannerEntry] = fast + medium + slow

  // MARK: - Fast Tier (process inspection, snapshot-only)

  static let fast: [ScannerEntry] = [
    ScannerEntry(id: "lolbin", name: "LOLBin Detector", tier: .fast) { ctx in
      await LOLBinDetector.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "stealth", name: "Stealth Scanner", tier: .fast) { ctx in
      await StealthScanner.shared.scanAll(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "process_integrity", name: "Process Integrity", tier: .fast) { ctx in
      await ProcessIntegrityChecker.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "credential_access", name: "Credential Access", tier: .fast) { ctx in
      await CredentialAccessDetector.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "dyld_env", name: "DYLD Injection", tier: .fast) { ctx in
      await DyldEnvDetector.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "masquerade", name: "Masquerade Detector", tier: .fast) { ctx in
      await MasqueradeDetector.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "hidden_process", name: "Hidden Processes", tier: .fast) { ctx in
      await HiddenProcessDetector.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "memory", name: "Memory Scanner", tier: .fast) { ctx in
      await MemoryScanner.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "fake_prompt", name: "Fake Prompt Detector", tier: .fast) { ctx in
      await FakePromptDetector.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "exploit_tool", name: "Exploit Tool Detector", tier: .fast) { ctx in
      await ExploitToolDetector.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "thread_anomaly", name: "Thread Anomaly", tier: .fast) { ctx in
      await ThreadAnomalyScanner.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "clipboard", name: "Clipboard Scanner", tier: .fast) { ctx in
      await ClipboardScanner.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "network_anomaly", name: "Network Anomaly", tier: .fast) { ctx in
      (await NetworkAnomalyDetector.shared.scanConnections(ctx.connections)).map { na in
        ProcessAnomaly(pid: 0, processName: na.processName, processPath: "",
          parentPID: 0, parentName: "", technique: na.type.rawValue,
          description: na.description, severity: na.severity,
          scannerId: "network_anomaly",
          enumMethod: "Network.framework connection analysis",
          evidence: [
            "remote: \(na.remoteAddress)",
            "connections: \(na.connectionCount)",
          ])
      }
    },
    ScannerEntry(id: "cloud_c2", name: "Cloud C2 Detector", tier: .fast) { ctx in
      await CloudC2Detector.shared.scan(connections: ctx.connections)
    },
    ScannerEntry(id: "env_keying", name: "Environmental Keying", tier: .fast) { ctx in
      await EnvironmentalKeyingDetector.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "process_hollowing", name: "Process Hollowing", tier: .fast) { ctx in
      await ProcessHollowingDetector.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "inline_hook", name: "Inline Hook Detector", tier: .fast) { ctx in
      await InlineHookDetector.shared.scan(snapshot: ctx.snapshot)
    },
  ]

  // MARK: - Medium Tier (filesystem reads, plist parsing, sqlite)

  static let medium: [ScannerEntry] = [
    ScannerEntry(id: "xpc_services", name: "XPC Services", tier: .medium) { _ in
      await XPCServiceAuditor.shared.scanXPCServices()
    },
    ScannerEntry(id: "mach_services", name: "Mach Services", tier: .medium) { _ in
      await XPCServiceAuditor.shared.scanMachServices()
    },
    ScannerEntry(id: "kext", name: "Kext Anomaly", tier: .medium) { _ in
      await KextAnomalyDetector.shared.scan()
    },
    ScannerEntry(id: "auth_db", name: "Authorization DB", tier: .medium) { _ in
      await AuthorizationDBMonitor.shared.scan()
    },
    ScannerEntry(id: "persistence", name: "Persistence Scanner", tier: .medium) { _ in
      (await PersistenceScanner.shared.scanAll()).filter(\.isSuspicious).map { item in
        ProcessAnomaly(pid: 0, processName: item.name, processPath: item.path,
          parentPID: 0, parentName: "",
          technique: "Suspicious \(item.type.rawValue)",
          description: item.suspicionReasons.joined(separator: "; "),
          severity: item.signingStatus == .unsigned ? .high : .medium, mitreID: "T1547",
          scannerId: "persistence",
          enumMethod: "FileManager.contentsOfDirectory + plist/signing analysis",
          evidence: [
            "type: \(item.type.rawValue)",
            "signing: \(item.signingStatus)",
            "path: \(item.path)",
          ])
      }
    },
    ScannerEntry(id: "event_taps", name: "Event Taps", tier: .medium) { _ in
      (await EventTapScanner.shared.scan()).filter(\.isSuspicious).map { tap in
        ProcessAnomaly(pid: tap.tappingPID, processName: tap.tappingProcessName,
          processPath: tap.tappingProcessPath, parentPID: 0, parentName: "",
          technique: "Suspicious Event Tap",
          description: tap.suspicionReasons.joined(separator: "; "),
          severity: tap.isKeyboardTap ? .high : .medium, mitreID: "T1056.001",
          scannerId: "event_taps",
          enumMethod: "CGGetEventTapList → CGEventTapInformation",
          evidence: [
            "tapping_pid: \(tap.tappingPID)",
            "keyboard_tap: \(tap.isKeyboardTap)",
            "process: \(tap.tappingProcessName)",
          ])
      }
    },
    ScannerEntry(id: "tcc", name: "TCC Monitor", tier: .medium) { _ in
      (await TCCMonitor.shared.scan()).filter(\.isSuspicious).map { entry in
        ProcessAnomaly(pid: 0, processName: entry.client, processPath: "",
          parentPID: 0, parentName: "", technique: "Suspicious TCC Grant",
          description: entry.suspicionReason ?? "Suspicious: \(entry.serviceName)",
          severity: .high, mitreID: "T1005",
          scannerId: "tcc",
          enumMethod: "SQLiteReader → TCC.db access table query",
          evidence: [
            "client: \(entry.client)",
            "service: \(entry.serviceName)",
          ])
      }
    },
    ScannerEntry(id: "ransomware", name: "Ransomware Detector", tier: .medium) { _ in
      (await RansomwareDetector.shared.getAlerts()).map { alert in
        ProcessAnomaly(pid: alert.processID, processName: alert.processName,
          processPath: alert.processPath, parentPID: 0, parentName: "",
          technique: "Ransomware Behavior",
          description: "Encrypted \(alert.encryptedFiles.count) files (entropy: \(String(format: "%.2f", alert.entropy)))",
          severity: .critical, mitreID: "T1486",
          scannerId: "ransomware",
          enumMethod: "ES_EVENT_TYPE_NOTIFY_WRITE entropy analysis",
          evidence: [
            "pid: \(alert.processID)",
            "files_encrypted: \(alert.encryptedFiles.count)",
            "entropy: \(String(format: "%.2f", alert.entropy))",
          ])
      }
    },
    ScannerEntry(id: "system_integrity", name: "System Integrity", tier: .medium) { _ in
      await SystemIntegrityScanner.shared.scan()
    },
    ScannerEntry(id: "network_config", name: "Network Config", tier: .medium) { _ in
      await NetworkConfigAuditor.shared.scan()
    },
    ScannerEntry(id: "staging", name: "Staging Detector", tier: .medium) { _ in
      await StagingDetector.shared.scan()
    },
    ScannerEntry(id: "xattr", name: "Xattr Abuse", tier: .medium) { _ in
      await XattrAbuseDetector.shared.scan()
    },
    ScannerEntry(id: "hidden_files", name: "Hidden Files", tier: .medium) { _ in
      await HiddenFileDetector.shared.scan()
    },
    ScannerEntry(id: "usb", name: "USB Devices", tier: .medium) { _ in
      await USBDeviceScanner.shared.scan()
    },
    ScannerEntry(id: "log_integrity", name: "Log Integrity", tier: .medium) { _ in
      await LogIntegrityScanner.shared.scan()
    },
    ScannerEntry(id: "screen_capture", name: "Screen Capture", tier: .medium) { _ in
      await ScreenCaptureScanner.shared.scan()
    },
    ScannerEntry(id: "covert_channel", name: "Covert Channel", tier: .medium) { _ in
      await CovertChannelDetector.shared.scan()
    },
    ScannerEntry(id: "firewall", name: "Firewall Auditor", tier: .medium) { _ in
      await FirewallRoutingAuditor.shared.scan()
    },
    ScannerEntry(id: "mach_port", name: "Mach Port Scanner", tier: .medium) { _ in
      await MachPortScanner.shared.scan()
    },
    ScannerEntry(id: "script_backdoor", name: "Script Backdoors", tier: .medium) { _ in
      await ScriptBackdoorScanner.shared.scan()
    },
    ScannerEntry(id: "download_provenance", name: "Download Provenance", tier: .medium) { _ in
      await DownloadProvenanceScanner.shared.scan()
    },
    ScannerEntry(id: "crash_reports", name: "Crash Reports", tier: .medium) { _ in
      await CrashReportAnalyzer.shared.scan()
    },
    ScannerEntry(id: "dns_tunnel", name: "DNS Tunneling", tier: .medium) { _ in
      (await DNSTunnelingDetector.shared.analyze()).map { na in
        ProcessAnomaly(pid: 0, processName: na.processName, processPath: "",
          parentPID: 0, parentName: "", technique: na.type.rawValue,
          description: na.description, severity: na.severity,
          scannerId: "dns_tunnel",
          enumMethod: "DNS query log entropy + subdomain length analysis",
          evidence: [
            "remote: \(na.remoteAddress)",
            "connections: \(na.connectionCount)",
          ])
      }
    },
    ScannerEntry(id: "persistence_monitor", name: "Persistence Monitor", tier: .medium) { _ in
      (await PersistenceMonitor.shared.diffAgainstSnapshot()).map { change in
        ProcessAnomaly.filesystem(
          name: change.processName.isEmpty ? (change.path as NSString).lastPathComponent : change.processName,
          path: change.path,
          technique: "Persistence \(change.eventType.rawValue.capitalized)",
          description: "\(change.persistenceType.rawValue) \(change.eventType.rawValue): \(change.path)\(change.pid > 0 ? " by PID \(change.pid)" : "")",
          severity: change.eventType == .deleted ? .medium : .high,
          mitreID: "T1547",
          scannerId: "persistence_monitor",
          enumMethod: "SHA256 snapshot diff of persistence locations",
          evidence: [
            "path: \(change.path)",
            "type: \(change.persistenceType.rawValue)",
            "event: \(change.eventType.rawValue)",
            "pid: \(change.pid)",
          ])
      }
    },
    ScannerEntry(id: "timestomp", name: "Timestomp Detector", tier: .medium) { _ in
      await TimestompDetector.shared.scan()
    },
  ]

  // MARK: - Slow Tier (codesign, docker, network calls)

  static let slow: [ScannerEntry] = [
    ScannerEntry(id: "binary_integrity", name: "Binary Integrity", tier: .slow) { ctx in
      await BinaryIntegrityScanner.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "dylib_hijack", name: "Dylib Hijack", tier: .slow) { ctx in
      (await DylibHijackScanner.shared.scanRunningProcesses(snapshot: ctx.snapshot))
        .filter(\.isActiveHijack).map { h in
          ProcessAnomaly(pid: 0, processName: h.binaryName, processPath: h.binaryPath,
            parentPID: 0, parentName: "", technique: h.type.rawValue,
            description: h.details, severity: .high, mitreID: "T1574.004",
            scannerId: "dylib_hijack",
            enumMethod: "otool -L + rpath/LC_LOAD_DYLIB analysis",
            evidence: [
              "binary: \(h.binaryName)",
              "path: \(h.binaryPath)",
              "hijack_type: \(h.type.rawValue)",
            ])
        }
    },
    ScannerEntry(id: "certificate", name: "Certificate Auditor", tier: .slow) { _ in
      await CertificateAuditor.shared.scan()
    },
    ScannerEntry(id: "browser_ext", name: "Browser Extensions", tier: .slow) { _ in
      await BrowserExtensionScanner.shared.scan()
    },
    ScannerEntry(id: "entitlement", name: "Entitlement Scanner", tier: .slow) { ctx in
      await EntitlementScanner.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "security_evasion", name: "Security Tool Evasion", tier: .slow) { ctx in
      await SecurityToolEvasionDetector.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "vm_container", name: "VM/Container Detector", tier: .slow) { ctx in
      await VMContainerDetector.shared.scan(snapshot: ctx.snapshot)
    },
    ScannerEntry(id: "boot_security", name: "Boot Security", tier: .slow) { _ in
      await BootSecurityScanner.shared.scan()
    },
    ScannerEntry(id: "kernel_integrity", name: "Kernel Integrity", tier: .slow) { _ in
      await KernelIntegrityScanner.shared.scan()
    },
    ScannerEntry(id: "dyld_cache", name: "Dyld Cache", tier: .slow) { _ in
      await DyldCacheScanner.shared.scan()
    },
    ScannerEntry(id: "iokit_driver", name: "IOKit Drivers", tier: .slow) { _ in
      await IOKitDriverScanner.shared.scan()
    },
    ScannerEntry(id: "app_audit", name: "Application Auditor", tier: .slow) { _ in
      await ApplicationAuditor.shared.scan()
    },
    ScannerEntry(id: "browser_history", name: "Browser History", tier: .slow) { _ in
      await BrowserHistoryScanner.shared.scan()
    },
    ScannerEntry(id: "supply_chain", name: "Supply Chain Auditor", tier: .slow) { _ in
      (await SupplyChainAuditor.shared.auditAll()).map { finding in
        ProcessAnomaly(pid: 0, processName: finding.packageName, processPath: "",
          parentPID: 0, parentName: "",
          technique: "Supply Chain \(finding.source.rawValue)",
          description: finding.finding + ": " + finding.details,
          severity: finding.severity, mitreID: "T1195",
          scannerId: "supply_chain",
          enumMethod: "Package manager audit (\(finding.source.rawValue))",
          evidence: [
            "source: \(finding.source.rawValue)",
            "package: \(finding.packageName)",
          ])
      }
    },
    ScannerEntry(id: "phantom_dylib", name: "Phantom Dylib", tier: .slow) { ctx in
      await PhantomDylibDetector.shared.scan(snapshot: ctx.snapshot)
    },
  ]
}
