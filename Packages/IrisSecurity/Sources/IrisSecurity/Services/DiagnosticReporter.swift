import Foundation
import os.log

/// Writes all detection results to a structured JSONL file that both the UI
/// and external tools (like Claude) can read.
///
/// Every scan result, every integrity probe, every alert gets persisted here.
/// The file at ~/Library/Application Support/Iris/diagnostics.jsonl is the
/// single source of truth — what the user sees in the UI is exactly what
/// an external reader sees in this file.
///
/// Format: one JSON object per line (JSONL), newest last. Auto-rotated at 10MB.
public actor DiagnosticReporter {
    public static let shared = DiagnosticReporter()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "Diagnostics")

    private let reportDir: URL
    private let reportFile: URL
    private let snapshotFile: URL
    private let encoder: JSONEncoder

    private init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        reportDir = appSupport.appendingPathComponent("Iris", isDirectory: true)
        reportFile = reportDir.appendingPathComponent("diagnostics.jsonl")
        snapshotFile = reportDir.appendingPathComponent("latest-snapshot.json")

        encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]

        try? FileManager.default.createDirectory(at: reportDir, withIntermediateDirectories: true)
    }

    // MARK: - Event Recording

    /// Record a scan completion with all findings
    public func recordScanResults(_ anomalies: [ProcessAnomaly], scannerTimings: [(id: String, duration: TimeInterval)]) {
        let entry = DiagnosticEntry(
            type: .scanComplete,
            timestamp: Date(),
            anomalies: anomalies.map { DiagnosticAnomaly(from: $0) },
            scannerTimings: scannerTimings.map { DiagnosticTiming(id: $0.id, durationMs: Int($0.duration * 1000)) },
            integrityResults: nil,
            systemState: nil
        )
        append(entry)
    }

    /// Record integrity probe results
    public func recordIntegrityResults(_ anomalies: [ProcessAnomaly], probeName: String) {
        let entry = DiagnosticEntry(
            type: .integrityProbe,
            timestamp: Date(),
            anomalies: anomalies.map { DiagnosticAnomaly(from: $0) },
            scannerTimings: nil,
            integrityResults: DiagnosticIntegrity(probe: probeName, findingCount: anomalies.count),
            systemState: nil
        )
        append(entry)
    }

    /// Write a complete system snapshot — replaces latest-snapshot.json
    /// This is the primary file for external readers to get current state.
    public func writeSnapshot(
        processCount: Int,
        connectionCount: Int,
        alertCount: Int,
        anomalies: [ProcessAnomaly],
        integrityStatus: [String: String] // probe name → "clean" or description
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

        guard let data = try? encoder.encode(snapshot) else { return }

        // Pretty-print the snapshot for easy reading
        let prettyEncoder = JSONEncoder()
        prettyEncoder.dateEncodingStrategy = .iso8601
        prettyEncoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let prettyData = (try? prettyEncoder.encode(snapshot)) ?? data

        try? prettyData.write(to: snapshotFile, options: .atomic)
        logger.info("Snapshot written: \(anomalies.count) anomalies, \(integrityStatus.count) probes")
    }

    /// Get the path where the snapshot is written (for external tools)
    public nonisolated var snapshotPath: String {
        snapshotFile.path
    }

    public nonisolated var logPath: String {
        reportFile.path
    }

    // MARK: - Private

    private func append(_ entry: DiagnosticEntry) {
        guard var data = try? encoder.encode(entry) else { return }
        data.append(0x0A) // newline

        // Rotate if too large (10MB)
        if let attrs = try? FileManager.default.attributesOfItem(atPath: reportFile.path),
           let size = attrs[.size] as? UInt64, size > 10_000_000 {
            let rotated = reportDir.appendingPathComponent("diagnostics-\(Int(Date().timeIntervalSince1970)).jsonl")
            try? FileManager.default.moveItem(at: reportFile, to: rotated)
        }

        if let fh = try? FileHandle(forWritingTo: reportFile) {
            fh.seekToEndOfFile()
            fh.write(data)
            try? fh.close()
        } else {
            try? data.write(to: reportFile)
        }
    }
}

// MARK: - Codable Models

struct DiagnosticEntry: Codable {
    let type: DiagnosticType
    let timestamp: Date
    let anomalies: [DiagnosticAnomaly]?
    let scannerTimings: [DiagnosticTiming]?
    let integrityResults: DiagnosticIntegrity?
    let systemState: DiagnosticSystemState?
}

enum DiagnosticType: String, Codable {
    case scanComplete
    case integrityProbe
    case alert
    case snapshot
}

struct DiagnosticAnomaly: Codable {
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
    let timestamp: Date

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
        self.timestamp = a.timestamp
    }
}

struct DiagnosticTiming: Codable {
    let id: String
    let durationMs: Int
}

struct DiagnosticIntegrity: Codable {
    let probe: String
    let findingCount: Int
}

struct DiagnosticSystemState: Codable {
    let sipEnabled: Bool?
    let amfiEnabled: Bool?
    let processCount: Int?
    let connectionCount: Int?
}

struct DiagnosticSnapshot: Codable {
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
