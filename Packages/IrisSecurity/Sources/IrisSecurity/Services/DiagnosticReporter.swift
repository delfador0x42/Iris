import Foundation
import os.log

/// Writes all detection results to structured files that both the UI
/// and external tools (Claude, iris-ctl) can read.
///
/// Three output channels:
/// 1. diagnostics.jsonl — append-only event log (scan results, alerts, probes)
/// 2. latest-snapshot.json — current system state (overwritten each scan)
/// 3. alerts.jsonl — real-time detection alerts (append-only, rotated at 5MB)
///
/// Format: JSONL (one JSON object per line), newest last. Auto-rotated.
public actor DiagnosticReporter {
    public static let shared = DiagnosticReporter()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "Diagnostics")

    private let reportDir: URL
    private let reportFile: URL
    private let snapshotFile: URL
    private let alertFile: URL
    private let exportFile: URL
    private let encoder: JSONEncoder
    private let prettyEncoder: JSONEncoder

    private init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        reportDir = appSupport.appendingPathComponent("Iris", isDirectory: true)
        reportFile = reportDir.appendingPathComponent("diagnostics.jsonl")
        snapshotFile = reportDir.appendingPathComponent("latest-snapshot.json")
        alertFile = reportDir.appendingPathComponent("alerts.jsonl")
        exportFile = reportDir.appendingPathComponent("latest-export.json")

        encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]

        prettyEncoder = JSONEncoder()
        prettyEncoder.dateEncodingStrategy = .iso8601
        prettyEncoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        try? FileManager.default.createDirectory(at: reportDir, withIntermediateDirectories: true)
    }

    // MARK: - Scan Results

    public func recordScanResults(_ anomalies: [ProcessAnomaly], scannerTimings: [(id: String, duration: TimeInterval)]) {
        let entry = DiagnosticEntry(
            type: .scanComplete,
            timestamp: Date(),
            anomalies: anomalies.map { DiagnosticAnomaly(from: $0) },
            scannerTimings: scannerTimings.map { DiagnosticTiming(id: $0.id, durationMs: Int($0.duration * 1000)) },
            integrityResults: nil,
            alert: nil
        )
        append(entry, to: reportFile, maxSize: 10_000_000)
    }

    // MARK: - Integrity Probes

    public func recordIntegrityResults(_ anomalies: [ProcessAnomaly], probeName: String) {
        let entry = DiagnosticEntry(
            type: .integrityProbe,
            timestamp: Date(),
            anomalies: anomalies.map { DiagnosticAnomaly(from: $0) },
            scannerTimings: nil,
            integrityResults: DiagnosticIntegrity(probe: probeName, findingCount: anomalies.count),
            alert: nil
        )
        append(entry, to: reportFile, maxSize: 10_000_000)
    }

    // MARK: - Real-Time Alerts

    /// Record a detection alert. Called by AlertStore on every new alert.
    public func recordAlert(_ alert: DiagnosticAlert) {
        let entry = DiagnosticEntry(
            type: .alert,
            timestamp: Date(),
            anomalies: nil,
            scannerTimings: nil,
            integrityResults: nil,
            alert: alert
        )
        append(entry, to: alertFile, maxSize: 5_000_000)
    }

    // MARK: - Snapshots

    public func writeSnapshot(
        processCount: Int,
        connectionCount: Int,
        alertCount: Int,
        anomalies: [ProcessAnomaly],
        integrityStatus: [String: String]
    ) {
        let snapshot = DiagnosticSnapshot(
            timestamp: Date(),
            processCount: processCount,
            connectionCount: connectionCount,
            alertCount: alertCount,
            anomalyCount: anomalies.count,
            criticalCount: anomalies.filter { $0.severity == .critical }.count,
            highCount: anomalies.filter { $0.severity == .high }.count,
            anomalies: anomalies.map { DiagnosticAnomaly(from: $0) },
            integrityStatus: integrityStatus
        )
        guard let data = try? prettyEncoder.encode(snapshot) else { return }
        try? data.write(to: snapshotFile, options: .atomic)
        logger.info("Snapshot: \(anomalies.count) anomalies, \(integrityStatus.count) probes")
    }

    // MARK: - Full Export (for CLI consumption)

    /// Write comprehensive export combining scan results, alerts, probes, and stats.
    /// This is the primary file iris-ctl reads for the `export` command.
    public func writeExport(_ export: DiagnosticExport) {
        guard let data = try? prettyEncoder.encode(export) else { return }
        try? data.write(to: exportFile, options: .atomic)
        logger.info("Export: \(export.findings.count) findings, \(export.alerts.count) alerts")
    }

    // MARK: - Paths (for external tools)

    public nonisolated var snapshotPath: String { snapshotFile.path }
    public nonisolated var logPath: String { reportFile.path }
    public nonisolated var alertPath: String { alertFile.path }
    public nonisolated var exportPath: String { exportFile.path }
    public nonisolated var dirPath: String { reportDir.path }

    // MARK: - Private

    private func append(_ entry: DiagnosticEntry, to file: URL, maxSize: UInt64) {
        guard var data = try? encoder.encode(entry) else { return }
        data.append(0x0A)

        if let attrs = try? FileManager.default.attributesOfItem(atPath: file.path),
           let size = attrs[.size] as? UInt64, size > maxSize {
            let stem = file.deletingPathExtension().lastPathComponent
            let ext = file.pathExtension
            let rotated = reportDir.appendingPathComponent("\(stem)-\(Int(Date().timeIntervalSince1970)).\(ext)")
            try? FileManager.default.moveItem(at: file, to: rotated)
        }

        if let fh = try? FileHandle(forWritingTo: file) {
            fh.seekToEndOfFile()
            fh.write(data)
            try? fh.close()
        } else {
            try? data.write(to: file)
        }
    }
}

// MARK: - Codable Models

struct DiagnosticEntry: Codable, Sendable {
    let type: DiagnosticType
    let timestamp: Date
    let anomalies: [DiagnosticAnomaly]?
    let scannerTimings: [DiagnosticTiming]?
    let integrityResults: DiagnosticIntegrity?
    let alert: DiagnosticAlert?
}

enum DiagnosticType: String, Codable, Sendable {
    case scanComplete
    case integrityProbe
    case alert
}

public struct DiagnosticAlert: Codable, Sendable {
    public let ruleId: String
    public let name: String
    public let severity: String
    public let mitreId: String
    public let processName: String
    public let processPath: String
    public let description: String
    public let timestamp: Date

    public init(ruleId: String, name: String, severity: String, mitreId: String,
                processName: String, processPath: String, description: String, timestamp: Date) {
        self.ruleId = ruleId
        self.name = name
        self.severity = severity
        self.mitreId = mitreId
        self.processName = processName
        self.processPath = processPath
        self.description = description
        self.timestamp = timestamp
    }
}

public struct DiagnosticAnomaly: Codable, Sendable {
    public let pid: Int32
    public let processName: String
    public let processPath: String
    public let technique: String
    public let description: String
    public let severity: String
    public let mitreID: String?
    public let scannerId: String
    public let enumMethod: String
    public let evidence: [String]
    public let timestamp: Date

    public init(from a: ProcessAnomaly) {
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
        self.timestamp = a.timestamp
    }
}

public struct DiagnosticTiming: Codable, Sendable {
    public let id: String
    public let durationMs: Int

    public init(id: String, durationMs: Int) {
        self.id = id
        self.durationMs = durationMs
    }
}

struct DiagnosticIntegrity: Codable, Sendable {
    let probe: String
    let findingCount: Int
}

struct DiagnosticSnapshot: Codable, Sendable {
    let timestamp: Date
    let processCount: Int
    let connectionCount: Int
    let alertCount: Int
    let anomalyCount: Int
    let criticalCount: Int
    let highCount: Int
    let anomalies: [DiagnosticAnomaly]
    let integrityStatus: [String: String]
}

/// Comprehensive export combining all detection outputs.
/// Written to latest-export.json for iris-ctl consumption.
public struct DiagnosticExport: Codable, Sendable {
    public let timestamp: Date
    public let scanDurationMs: Int
    public let scannerCount: Int

    // Findings
    public let findings: [DiagnosticAnomaly]
    public let criticalCount: Int
    public let highCount: Int
    public let mediumCount: Int

    // Per-scanner breakdown
    public let scannerTimings: [DiagnosticTiming]

    // Correlations
    public let correlationCount: Int
    public let campaignCount: Int

    // Real-time detection stats
    public let detectionStats: DetectionStats

    // Alerts (recent)
    public let alerts: [DiagnosticAlert]

    // Probe results
    public let probeResults: [ProbeExport]

    public init(timestamp: Date, scanDurationMs: Int, scannerCount: Int,
                findings: [DiagnosticAnomaly], criticalCount: Int, highCount: Int, mediumCount: Int,
                scannerTimings: [DiagnosticTiming], correlationCount: Int, campaignCount: Int,
                detectionStats: DetectionStats, alerts: [DiagnosticAlert], probeResults: [ProbeExport]) {
        self.timestamp = timestamp
        self.scanDurationMs = scanDurationMs
        self.scannerCount = scannerCount
        self.findings = findings
        self.criticalCount = criticalCount
        self.highCount = highCount
        self.mediumCount = mediumCount
        self.scannerTimings = scannerTimings
        self.correlationCount = correlationCount
        self.campaignCount = campaignCount
        self.detectionStats = detectionStats
        self.alerts = alerts
        self.probeResults = probeResults
    }
}

public struct DetectionStats: Codable, Sendable {
    public let eventsProcessed: UInt64
    public let alertsProduced: UInt64
    public let rulesLoaded: Int
    public let correlationRulesLoaded: Int
    public let busRunning: Bool
    public let busIngested: UInt64

    public init(eventsProcessed: UInt64, alertsProduced: UInt64, rulesLoaded: Int,
                correlationRulesLoaded: Int, busRunning: Bool, busIngested: UInt64) {
        self.eventsProcessed = eventsProcessed
        self.alertsProduced = alertsProduced
        self.rulesLoaded = rulesLoaded
        self.correlationRulesLoaded = correlationRulesLoaded
        self.busRunning = busRunning
        self.busIngested = busIngested
    }
}

public struct ProbeExport: Codable, Sendable {
    public let id: String
    public let name: String
    public let verdict: String
    public let contradictionCount: Int
    public let timestamp: Date

    public init(id: String, name: String, verdict: String, contradictionCount: Int, timestamp: Date) {
        self.id = id
        self.name = name
        self.verdict = verdict
        self.contradictionCount = contradictionCount
        self.timestamp = timestamp
    }
}
