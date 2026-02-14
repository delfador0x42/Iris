import Foundation
import os.log

/// Runs all security checks and computes an overall security grade.
/// Entry point for the security assessment engine.
/// Runs system-level checks AND all threat scanners for a complete picture.
public actor SecurityAssessor {
    public static let shared = SecurityAssessor()

    private let logger = Logger(subsystem: "com.wudan.iris", category: "SecurityAssessor")

    /// Run all security checks and return results with grade
    public func assess() async -> (checks: [SecurityCheck], grade: SecurityGrade) {
        logger.info("Starting security assessment")

        var allChecks: [SecurityCheck] = []

        // System-level checks (SIP, FileVault, Gatekeeper, Firewall, etc.)
        let systemChecks = await SystemSecurityChecks.runAll()
        allChecks.append(contentsOf: systemChecks)

        // Run all threat scanners concurrently and convert findings to SecurityChecks
        let threatChecks = await runThreatScanners()
        allChecks.append(contentsOf: threatChecks)

        // Sort by severity (critical first) then by category
        allChecks.sort { lhs, rhs in
            if lhs.severity != rhs.severity { return lhs.severity > rhs.severity }
            return lhs.category.rawValue < rhs.category.rawValue
        }

        let grade = SecurityGrade.compute(from: allChecks)
        logger.info("Assessment complete: \(grade.letter) (\(grade.score)/100), \(allChecks.count) checks")

        return (allChecks, grade)
    }

    /// Run all threat scanners and convert anomalies into SecurityChecks
    private func runThreatScanners() async -> [SecurityCheck] {
        let snapshot = ProcessSnapshot.capture()

        // Fire all scanners concurrently
        async let r1 = LOLBinDetector.shared.scan(snapshot: snapshot)
        async let r2 = StealthScanner.shared.scanAll(snapshot: snapshot)
        async let r3a = XPCServiceAuditor.shared.scanXPCServices()
        async let r3b = XPCServiceAuditor.shared.scanMachServices()
        async let r4 = NetworkAnomalyDetector.shared.scanCurrentConnections()
        async let r5 = ProcessIntegrityChecker.shared.scan(snapshot: snapshot)
        async let r6 = CredentialAccessDetector.shared.scan(snapshot: snapshot)
        async let r7 = KextAnomalyDetector.shared.scan()
        async let r8 = AuthorizationDBMonitor.shared.scan()
        async let r9 = DyldEnvDetector.shared.scan(snapshot: snapshot)
        async let r10 = PersistenceScanner.shared.scanAll()
        async let r11 = EventTapScanner.shared.scan()
        async let r12 = DylibHijackScanner.shared.scanRunningProcesses(snapshot: snapshot)
        async let r13 = TCCMonitor.shared.scan()
        async let r14 = SupplyChainAuditor.shared.auditAll()
        async let r15 = RansomwareDetector.shared.getAlerts()

        // Collect all ProcessAnomaly results
        var anomalies: [ProcessAnomaly] = []
        anomalies.append(contentsOf: await r1)
        anomalies.append(contentsOf: await r2)
        anomalies.append(contentsOf: await r3a)
        anomalies.append(contentsOf: await r3b)
        anomalies.append(contentsOf: (await r4).map { na in
            ProcessAnomaly(
                pid: 0, processName: na.processName, processPath: "",
                parentPID: 0, parentName: "",
                technique: na.type.rawValue,
                description: na.description, severity: na.severity
            )
        })
        anomalies.append(contentsOf: await r5)
        anomalies.append(contentsOf: await r6)
        anomalies.append(contentsOf: await r7)
        anomalies.append(contentsOf: await r8)
        anomalies.append(contentsOf: await r9)
        anomalies.append(contentsOf: (await r10).filter(\.isSuspicious).map { item in
            ProcessAnomaly(
                pid: 0, processName: item.name, processPath: item.path,
                parentPID: 0, parentName: "",
                technique: "Suspicious \(item.type.rawValue)",
                description: item.suspicionReasons.joined(separator: "; "),
                severity: item.signingStatus == .unsigned ? .high : .medium,
                mitreID: "T1547"
            )
        })
        anomalies.append(contentsOf: (await r11).filter(\.isSuspicious).map { tap in
            ProcessAnomaly(
                pid: tap.tappingPID, processName: tap.tappingProcessName,
                processPath: tap.tappingProcessPath,
                parentPID: 0, parentName: "",
                technique: "Suspicious Event Tap",
                description: tap.suspicionReasons.joined(separator: "; "),
                severity: tap.isKeyboardTap ? .high : .medium,
                mitreID: "T1056.001"
            )
        })
        anomalies.append(contentsOf: (await r12).filter(\.isActiveHijack).map { h in
            ProcessAnomaly(
                pid: 0, processName: h.binaryName, processPath: h.binaryPath,
                parentPID: 0, parentName: "",
                technique: h.type.rawValue,
                description: h.details, severity: .high, mitreID: "T1574.004"
            )
        })
        anomalies.append(contentsOf: (await r13).filter(\.isSuspicious).map { entry in
            ProcessAnomaly(
                pid: 0, processName: entry.client, processPath: "",
                parentPID: 0, parentName: "",
                technique: "Suspicious TCC Grant",
                description: entry.suspicionReason ?? "Suspicious permission: \(entry.serviceName)",
                severity: .high, mitreID: "T1005"
            )
        })
        anomalies.append(contentsOf: (await r14).map { finding in
            ProcessAnomaly(
                pid: 0, processName: finding.packageName, processPath: "",
                parentPID: 0, parentName: "",
                technique: "Supply Chain: \(finding.finding)",
                description: finding.details,
                severity: finding.severity, mitreID: "T1195"
            )
        })
        anomalies.append(contentsOf: (await r15).map { alert in
            ProcessAnomaly(
                pid: alert.processID, processName: alert.processName,
                processPath: alert.processPath,
                parentPID: 0, parentName: "",
                technique: "Ransomware Behavior",
                description: "Encrypted \(alert.encryptedFiles.count) files (entropy: \(String(format: "%.2f", alert.entropy)))",
                severity: .critical, mitreID: "T1486"
            )
        })

        logger.info("Threat scanners found \(anomalies.count) anomalies")

        // Convert anomalies to SecurityChecks (each anomaly = one failed check)
        return anomalies.map { anomaly in
            let checkSeverity: CheckSeverity
            switch anomaly.severity {
            case .critical: checkSeverity = .critical
            case .high: checkSeverity = .high
            case .medium: checkSeverity = .medium
            case .low: checkSeverity = .low
            }

            return SecurityCheck(
                category: .threats,
                name: anomaly.technique,
                description: "\(anomaly.processName): \(anomaly.description)",
                status: .fail,
                severity: checkSeverity
            )
        }
    }
}
