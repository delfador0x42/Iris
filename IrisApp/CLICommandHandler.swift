import Foundation
import os.log

/// Receives commands from CLI tools via DistributedNotificationCenter.
/// Enables Claude Code and scripts to remote-control the running Iris app.
///
/// Usage from CLI:
///   swift scripts/iris-ctl.swift status       # System state
///   swift scripts/iris-ctl.swift scan         # Full scan with findings
///   swift scripts/iris-ctl.swift alerts       # Recent detection alerts
///   swift scripts/iris-ctl.swift export       # Comprehensive export (everything)
///   swift scripts/iris-ctl.swift probe        # Run all contradiction probes
///   swift scripts/iris-ctl.swift snapshot     # Latest snapshot
///   swift scripts/iris-ctl.swift stats        # Detection engine statistics
@MainActor
final class CLICommandHandler {
  static let shared = CLICommandHandler()

  private let logger = Logger(subsystem: "com.wudan.iris", category: "CLICommand")
  static let commandName = Notification.Name("com.wudan.iris.command")
  static let responseName = Notification.Name("com.wudan.iris.response")
  static let statusPath = "/tmp/iris-status.json"

  func startListening() {
    DistributedNotificationCenter.default().addObserver(
      forName: Self.commandName,
      object: nil,
      queue: .main
    ) { [weak self] notification in
      Task { @MainActor in
        await self?.handleCommand(notification)
      }
    }
    logger.info("CLI command handler listening")
  }

  private func handleCommand(_ notification: Notification) async {
    guard let action = notification.userInfo?["action"] as? String else { return }
    logger.info("CLI command: \(action)")

    switch action {
    case "status":
      await writeStatus()

    case "reinstall":
      ExtensionManager.shared.cleanReinstallExtensions()
      respond("ok", action: "reinstall")

    case "startProxy":
      let ok = await TransparentProxyManager.enableProxy()
      respond(ok ? "ok" : "failed", action: "startProxy")

    case "stopProxy":
      await TransparentProxyManager.disableProxy()
      respond("ok", action: "stopProxy")

    case "sendCA":
      await IrisMainApp.sendCAToProxy()
      respond("ok", action: "sendCA")

    case "checkExtensions":
      await ExtensionManager.shared.checkAllExtensionStatuses()
      await writeStatus()

    case "cleanProxy":
      await TransparentProxyManager.cleanConfiguration()
      let cleaned = await TransparentProxyManager.enableProxy()
      respond(cleaned ? "ok" : "failed", action: "cleanProxy")

    case "installNetwork":
      ExtensionManager.shared.installExtension(.network)
      respond("ok", action: "installNetwork")

    case "scan":
      await runFullScan()

    case "alerts":
      await writeAlerts()

    case "stats":
      await writeStats()

    case "export":
      await writeExport()

    case "snapshot":
      writeSnapshotPath()

    case "probe":
      await runProbes()

    case "probeOne":
      let probeId = notification.userInfo?["probeId"] as? String ?? ""
      await runOneProbe(id: probeId)

    case "probeStatus":
      writeProbeStatus()

    case "dump":
      await writeDump()

    case "watch":
      respondWithPath(EventLogger.shared.path, action: "watch")

    default:
      logger.warning("Unknown CLI command: \(action)")
      respond("error", action: action)
    }
  }

  // MARK: - Status

  private func writeStatus() async {
    await ExtensionManager.shared.checkAllExtensionStatuses()
    let em = ExtensionManager.shared
    let detStats = await DetectionEngine.shared.stats()
    let busStats = await SecurityEventBus.shared.stats()

    let status: [String: Any] = [
      "timestamp": ISO8601DateFormatter().string(from: Date()),
      "extensions": [
        "endpoint": em.endpointExtensionState.description,
        "network": em.networkExtensionState.description,
      ],
      "proxy": [
        "connected": ProxyStore.shared.isEnabled,
        "interception": ProxyStore.shared.isInterceptionEnabled,
        "flowCount": ProxyStore.shared.totalFlowCount,
      ],
      "ca": [
        "loaded": CertificateStore.shared.caCertificate != nil
      ],
      "detection": [
        "eventsProcessed": detStats.events,
        "alertsProduced": detStats.alerts,
        "rulesLoaded": detStats.rules,
        "correlationRules": detStats.correlations,
        "busRunning": busStats.running,
        "busIngested": busStats.ingested,
      ],
      "diagnostics": [
        "snapshotPath": DiagnosticReporter.shared.snapshotPath,
        "alertsPath": DiagnosticReporter.shared.alertPath,
        "logPath": DiagnosticReporter.shared.logPath,
        "exportPath": DiagnosticReporter.shared.exportPath,
        "eventStream": EventLogger.shared.path,
      ],
    ]

    if let data = try? JSONSerialization.data(
      withJSONObject: status, options: [.prettyPrinted, .sortedKeys])
    {
      try? data.write(to: URL(fileURLWithPath: Self.statusPath))
    }
    respond("ok", action: "status")
  }

  // MARK: - Full Scan (with findings)

  private func runFullScan() async {
    let start = Date()
    let result = await SecurityAssessor.shared.scanThreats { _ in }
    let elapsed = Date().timeIntervalSince(start)

    // Build comprehensive scan output
    let scanOutput = ScanOutput(
      timestamp: ISO8601DateFormatter().string(from: Date()),
      totalDurationMs: Int(elapsed * 1000),
      scannerCount: result.scannerCount,
      totalFindings: result.totalFindings,
      criticalCount: result.criticalCount,
      highCount: result.highCount,
      correlationCount: result.correlations.count,
      campaignCount: result.fusion.campaigns.count,
      findings: result.anomalies.map { ScanFinding(from: $0) },
      scannerTimings: result.scannerResults
        .sorted { $0.duration > $1.duration }
        .map { ScanTiming(id: $0.id, name: $0.name, durationMs: Int($0.duration * 1000), findings: $0.anomalies.count) },
      correlations: result.correlations.map { CorrelationOutput(from: $0) },
      campaigns: result.fusion.campaigns.map { CampaignOutput(from: $0) }
    )

    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? encoder.encode(scanOutput) {
      try? data.write(to: URL(fileURLWithPath: "/tmp/iris-scan-results.json"))
    }

    // Also write timing-only for backward compat
    let timings = result.scannerResults
      .sorted { $0.duration > $1.duration }
      .map { "\($0.name): \(String(format: "%.1f", $0.duration * 1000))ms (\($0.anomalies.count) findings)" }
    let timingReport: [String: Any] = [
      "timestamp": ISO8601DateFormatter().string(from: Date()),
      "totalDuration_ms": Int(elapsed * 1000),
      "scannerCount": result.scannerCount,
      "totalFindings": result.totalFindings,
      "criticalCount": result.criticalCount,
      "highCount": result.highCount,
      "scannerTiming": timings,
    ]
    if let data = try? JSONSerialization.data(
      withJSONObject: timingReport, options: [.prettyPrinted, .sortedKeys])
    {
      try? data.write(to: URL(fileURLWithPath: "/tmp/iris-scan-timing.json"))
    }

    logger.info("CLI scan: \(result.totalFindings) findings in \(String(format: "%.1f", elapsed))s")
    respond("ok", action: "scan")
  }

  // MARK: - Alerts

  private func writeAlerts() async {
    let alerts = await AlertStore.shared.recent(200)
    let output = alerts.map { alert in
      AlertOutput(
        ruleId: alert.ruleId, name: alert.name,
        severity: alert.severity.label, mitreId: alert.mitreId,
        processName: alert.processName, processPath: alert.processPath,
        description: alert.description,
        timestamp: ISO8601DateFormatter().string(from: alert.timestamp))
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? encoder.encode(output) {
      try? data.write(to: URL(fileURLWithPath: "/tmp/iris-alerts.json"))
    }
    respond("ok", action: "alerts")
  }

  // MARK: - Stats

  private func writeStats() async {
    let det = await DetectionEngine.shared.stats()
    let bus = await SecurityEventBus.shared.stats()
    let alertCounts = await AlertStore.shared.countBySeverity()

    let stats: [String: Any] = [
      "timestamp": ISO8601DateFormatter().string(from: Date()),
      "detection": [
        "eventsProcessed": det.events,
        "alertsProduced": det.alerts,
        "rulesLoaded": det.rules,
        "correlationRules": det.correlations,
      ],
      "eventBus": [
        "running": bus.running,
        "totalIngested": bus.ingested,
        "esSequence": bus.seq,
      ],
      "alertStore": [
        "critical": alertCounts[.critical] ?? 0,
        "high": alertCounts[.high] ?? 0,
        "medium": alertCounts[.medium] ?? 0,
        "low": alertCounts[.low] ?? 0,
        "total": alertCounts.values.reduce(0, +),
      ],
    ]

    if let data = try? JSONSerialization.data(
      withJSONObject: stats, options: [.prettyPrinted, .sortedKeys])
    {
      try? data.write(to: URL(fileURLWithPath: "/tmp/iris-stats.json"))
    }
    respond("ok", action: "stats")
  }

  // MARK: - Export (comprehensive)

  private func writeExport() async {
    // Use cached result or run a fresh scan
    let cached = await SecurityAssessor.shared.cachedResult
    let result: ThreatScanResult
    if let cached { result = cached }
    else { result = await SecurityAssessor.shared.scanThreats { _ in } }

    let det = await DetectionEngine.shared.stats()
    let bus = await SecurityEventBus.shared.stats()
    let alerts = await AlertStore.shared.recent(500)
    let probeResults = ProbeStore.readLatest()

    let export = DiagnosticExport(
      timestamp: Date(),
      scanDurationMs: Int(result.scanDuration * 1000),
      scannerCount: result.scannerCount,
      findings: result.anomalies.map { DiagnosticAnomaly(from: $0) },
      criticalCount: result.criticalCount,
      highCount: result.highCount,
      mediumCount: result.anomalies.filter { $0.severity == .medium }.count,
      scannerTimings: result.scannerResults.map {
        DiagnosticTiming(id: $0.id, durationMs: Int($0.duration * 1000))
      },
      correlationCount: result.correlations.count,
      campaignCount: result.fusion.campaigns.count,
      detectionStats: DetectionStats(
        eventsProcessed: det.events, alertsProduced: det.alerts,
        rulesLoaded: det.rules, correlationRulesLoaded: det.correlations,
        busRunning: bus.running, busIngested: bus.ingested),
      alerts: alerts.map {
        DiagnosticAlert(
          ruleId: $0.ruleId, name: $0.name, severity: $0.severity.label,
          mitreId: $0.mitreId, processName: $0.processName,
          processPath: $0.processPath, description: $0.description,
          timestamp: $0.timestamp)
      },
      probeResults: probeResults.map {
        ProbeExport(id: $0.probeId, name: $0.probeName, verdict: $0.verdict.rawValue,
                    contradictionCount: $0.comparisons.filter { !$0.matches }.count,
                    timestamp: $0.timestamp)
      }
    )

    await DiagnosticReporter.shared.writeExport(export)
    // Also write to /tmp for easy CLI access
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? encoder.encode(export) {
      try? data.write(to: URL(fileURLWithPath: "/tmp/iris-export.json"))
    }
    respond("ok", action: "export")
  }

  // MARK: - Snapshot

  private func writeSnapshotPath() {
    let path = DiagnosticReporter.shared.snapshotPath
    if FileManager.default.fileExists(atPath: path) {
      // Copy snapshot to /tmp for easy reading
      try? FileManager.default.copyItem(
        atPath: path, toPath: "/tmp/iris-snapshot.json")
    }
    respond("ok", action: "snapshot")
  }

  // MARK: - Probes

  private func runProbes() async {
    let runner = ProbeRunner.shared
    let results = await runner.runAll()
    let contradictions = results.filter { $0.verdict == .contradiction }.count

    // Write detailed results
    let output = results.map { r in
      ProbeOutput(
        id: r.probeId, name: r.probeName, verdict: r.verdict.rawValue,
        contradictions: r.comparisons.filter { !$0.matches }.map { c in
          ContradictionOutput(source1: c.sourceA.source, source2: c.sourceB.source,
                              value1: c.sourceA.value, value2: c.sourceB.value, label: c.label)
        },
        timestamp: ISO8601DateFormatter().string(from: r.timestamp))
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? encoder.encode(output) {
      try? data.write(to: URL(fileURLWithPath: "/tmp/iris-probes.json"))
    }

    logger.info("CLI probes: \(results.count) run, \(contradictions) contradictions")
    respond("ok", action: "probe")
  }

  private func runOneProbe(id: String) async {
    let runner = ProbeRunner.shared
    if let result = await runner.runOne(id: id) {
      let output = ProbeOutput(
        id: result.probeId, name: result.probeName, verdict: result.verdict.rawValue,
        contradictions: result.comparisons.filter { !$0.matches }.map { c in
          ContradictionOutput(source1: c.sourceA.source, source2: c.sourceB.source,
                              value1: c.sourceA.value, value2: c.sourceB.value, label: c.label)
        },
        timestamp: ISO8601DateFormatter().string(from: result.timestamp))
      let encoder = JSONEncoder()
      encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
      if let data = try? encoder.encode(output) {
        try? data.write(to: URL(fileURLWithPath: "/tmp/iris-probe-\(id).json"))
      }
      respond("ok", action: "probeOne")
    } else {
      respond("error: unknown probe '\(id)'", action: "probeOne")
    }
  }

  private func writeProbeStatus() {
    let results = ProbeStore.readLatest()
    let output = results.map { r in
      ProbeOutput(
        id: r.probeId, name: r.probeName, verdict: r.verdict.rawValue,
        contradictions: r.comparisons.filter { !$0.matches }.map { c in
          ContradictionOutput(source1: c.sourceA.source, source2: c.sourceB.source,
                              value1: c.sourceA.value, value2: c.sourceB.value, label: c.label)
        },
        timestamp: ISO8601DateFormatter().string(from: r.timestamp))
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? encoder.encode(output) {
      try? data.write(to: URL(fileURLWithPath: "/tmp/iris-probes.json"))
    }
    respond("ok", action: "probeStatus")
  }

  // MARK: - Dump (all store state)

  private func writeDump() async {
    let det = await DetectionEngine.shared.stats()
    let bus = await SecurityEventBus.shared.stats()
    let alerts = await AlertStore.shared.recent(500)
    let probeResults = ProbeStore.readLatest()

    let dump = FullDump(
      timestamp: Date(),
      processes: ProcessStore.shared.processes,
      processCount: ProcessStore.shared.totalCount,
      suspiciousCount: ProcessStore.shared.suspiciousCount,
      connections: SecurityStore.shared.connections,
      connectionCount: SecurityStore.shared.connections.count,
      totalBytesUp: SecurityStore.shared.totalBytesUp,
      totalBytesDown: SecurityStore.shared.totalBytesDown,
      dnsQueries: DNSStore.shared.queries,
      dnsQueryCount: DNSStore.shared.totalQueries,
      dnsTopDomains: DNSStore.shared.topDomains.prefix(20).map {
        TopDomain(domain: $0.domain, count: $0.count)
      },
      proxyFlowCount: ProxyStore.shared.totalFlowCount,
      proxyInterception: ProxyStore.shared.isInterceptionEnabled,
      alerts: alerts.map { a in
        AlertOutput(
          ruleId: a.ruleId, name: a.name, severity: a.severity.label,
          mitreId: a.mitreId, processName: a.processName,
          processPath: a.processPath, description: a.description,
          timestamp: ISO8601DateFormatter().string(from: a.timestamp))
      },
      detection: DumpDetectionStats(
        eventsProcessed: det.events, alertsProduced: det.alerts,
        rulesLoaded: det.rules, correlationRules: det.correlations,
        busRunning: bus.running, busIngested: bus.ingested),
      probes: probeResults.map { r in
        ProbeOutput(
          id: r.probeId, name: r.probeName, verdict: r.verdict.rawValue,
          contradictions: r.comparisons.filter { !$0.matches }.map { c in
            ContradictionOutput(
              source1: c.sourceA.source, source2: c.sourceB.source,
              value1: c.sourceA.value, value2: c.sourceB.value, label: c.label)
          },
          timestamp: ISO8601DateFormatter().string(from: r.timestamp))
      },
      eventStreamPath: EventLogger.shared.path
    )

    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? encoder.encode(dump) {
      try? data.write(to: URL(fileURLWithPath: "/tmp/iris-dump.json"))
    }
    respond("ok", action: "dump")
  }

  private func respondWithPath(_ path: String, action: String) {
    DistributedNotificationCenter.default().postNotificationName(
      Self.responseName,
      object: nil,
      userInfo: ["status": "ok", "action": action, "path": path],
      deliverImmediately: true)
  }

  private func respond(_ status: String, action: String) {
    DistributedNotificationCenter.default().postNotificationName(
      Self.responseName,
      object: nil,
      userInfo: ["status": status, "action": action],
      deliverImmediately: true
    )
  }
}

// MARK: - CLI Output Models

private struct ScanOutput: Codable {
  let timestamp: String
  let totalDurationMs: Int
  let scannerCount: Int
  let totalFindings: Int
  let criticalCount: Int
  let highCount: Int
  let correlationCount: Int
  let campaignCount: Int
  let findings: [ScanFinding]
  let scannerTimings: [ScanTiming]
  let correlations: [CorrelationOutput]
  let campaigns: [CampaignOutput]
}

private struct ScanFinding: Codable {
  let pid: Int32
  let processName: String
  let processPath: String
  let technique: String
  let description: String
  let severity: String
  let mitreID: String?
  let scannerId: String
  let enumMethod: String
  let evidence: [String]

  init(from a: ProcessAnomaly) {
    self.pid = a.pid
    self.processName = a.processName
    self.processPath = a.processPath
    self.technique = a.technique
    self.description = a.description
    self.severity = a.severity.label
    self.mitreID = a.mitreID
    self.scannerId = a.scannerId
    self.enumMethod = a.enumMethod
    self.evidence = a.evidence
  }
}

private struct ScanTiming: Codable {
  let id: String
  let name: String
  let durationMs: Int
  let findings: Int
}

private struct AlertOutput: Codable {
  let ruleId: String
  let name: String
  let severity: String
  let mitreId: String
  let processName: String
  let processPath: String
  let description: String
  let timestamp: String
}

private struct CorrelationOutput: Codable {
  let name: String
  let description: String
  let severity: String
  let scannerCount: Int
  let mitreChain: String

  init(from c: CorrelationEngine.Correlation) {
    self.name = c.name
    self.description = c.description
    self.severity = c.severity.label
    self.scannerCount = c.scannerIds.count
    self.mitreChain = c.mitreChain
  }
}

private struct CampaignOutput: Codable {
  let name: String
  let severity: String
  let confidence: Double
  let entityCount: Int
  let evidenceCount: Int

  init(from c: CampaignDetection) {
    self.name = c.name
    self.severity = c.severity.label
    self.confidence = c.confidence
    self.entityCount = c.entities.count
    self.evidenceCount = c.entities.reduce(0) { $0 + $1.evidence.count }
  }
}

private struct ProbeOutput: Codable {
  let id: String
  let name: String
  let verdict: String
  let contradictions: [ContradictionOutput]
  let timestamp: String
}

private struct ContradictionOutput: Codable {
  let source1: String
  let source2: String
  let value1: String
  let value2: String
  let label: String
}

// MARK: - Dump Models

private struct FullDump: Encodable {
  let timestamp: Date
  let processes: [ProcessInfo]
  let processCount: Int
  let suspiciousCount: Int
  let connections: [NetworkConnection]
  let connectionCount: Int
  let totalBytesUp: UInt64
  let totalBytesDown: UInt64
  let dnsQueries: [DNSQueryRecord]
  let dnsQueryCount: Int
  let dnsTopDomains: [TopDomain]
  let proxyFlowCount: Int
  let proxyInterception: Bool
  let alerts: [AlertOutput]
  let detection: DumpDetectionStats
  let probes: [ProbeOutput]
  let eventStreamPath: String
}

private struct TopDomain: Codable {
  let domain: String
  let count: Int
}

private struct DumpDetectionStats: Codable {
  let eventsProcessed: UInt64
  let alertsProduced: UInt64
  let rulesLoaded: Int
  let correlationRules: Int
  let busRunning: Bool
  let busIngested: UInt64
}
