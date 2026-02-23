import Foundation

/// Real-time unified event stream for external consumers (Claude, iris-ctl).
/// Writes JSONL to ~/Library/Logs/Iris/events.jsonl — one JSON object per line.
/// Three event types: "event" (SecurityEvent), "alert" (detection), "probe" (integrity).
public actor EventLogger {
    public static let shared = EventLogger()

    private let logFile: URL
    private let logDir: URL
    private let encoder: JSONEncoder
    private let maxSize: UInt64 = 10_000_000

    private init() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        logDir = home.appendingPathComponent("Library/Logs/Iris", isDirectory: true)
        logFile = logDir.appendingPathComponent("events.jsonl")
        encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)
    }

    /// Log raw SecurityEvents from the event bus
    public func log(_ events: [SecurityEvent]) {
        guard !events.isEmpty else { return }
        var buf = Data()
        for e in events {
            let line = EventLine(
                ts: e.timestamp, source: e.source.rawValue,
                eventType: e.eventType, pid: e.pid,
                process: e.processName, path: e.processPath,
                signingId: e.signingId,
                appleSigned: e.isAppleSigned,
                fields: e.fields.isEmpty ? nil : e.fields
            )
            if let data = try? encoder.encode(line) {
                buf.append(data)
                buf.append(0x0A)
            }
        }
        append(buf)
    }

    /// Log a detection alert
    public func log(_ alert: SecurityAlert) {
        let line = AlertLine(
            ts: alert.timestamp, ruleId: alert.ruleId,
            name: alert.name, severity: alert.severity.label,
            mitreId: alert.mitreId, process: alert.processName,
            path: alert.processPath, desc: alert.description
        )
        guard var data = try? encoder.encode(line) else { return }
        data.append(0x0A)
        append(data)
    }

    /// Log a probe result
    public func logProbe(id: String, name: String, verdict: String, contradictions: Int) {
        let line = ProbeLine(
            ts: Date(), probeId: id, name: name,
            verdict: verdict, contradictions: contradictions
        )
        guard var data = try? encoder.encode(line) else { return }
        data.append(0x0A)
        append(data)
    }

    /// Path for external tools (tail -f, iris-ctl watch)
    public nonisolated var path: String { logFile.path }

    // MARK: - Private

    private func append(_ data: Data) {
        guard !data.isEmpty else { return }
        rotate()
        if let fh = try? FileHandle(forWritingTo: logFile) {
            fh.seekToEndOfFile()
            fh.write(data)
            try? fh.close()
        } else {
            try? data.write(to: logFile)
        }
    }

    private func rotate() {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: logFile.path),
              let size = attrs[.size] as? UInt64, size > maxSize else { return }
        let rotated = logDir.appendingPathComponent(
            "events-\(Int(Date().timeIntervalSince1970)).jsonl")
        try? FileManager.default.moveItem(at: logFile, to: rotated)
    }
}

// MARK: - Line Types (flat JSON, no nesting)

private struct EventLine: Encodable {
    let type = "event"
    let ts: Date
    let source: String
    let eventType: String
    let pid: Int32
    let process: String
    let path: String
    let signingId: String?
    let appleSigned: Bool
    let fields: [String: String]?
}

private struct AlertLine: Encodable {
    let type = "alert"
    let ts: Date
    let ruleId: String
    let name: String
    let severity: String
    let mitreId: String
    let process: String
    let path: String
    let desc: String
}

private struct ProbeLine: Encodable {
    let type = "probe"
    let ts: Date
    let probeId: String
    let name: String
    let verdict: String
    let contradictions: Int
}
