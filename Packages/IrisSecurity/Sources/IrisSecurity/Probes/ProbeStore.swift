import Foundation
import os.log

/// Reads/writes probe results to ~/.iris/probes/ as JSON.
/// Claude reads these via `cat ~/.iris/probes/latest.json`.
public enum ProbeStore {
    private static let logger = Logger(subsystem: "com.wudan.iris", category: "ProbeStore")

    private static var probesDir: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".iris/probes", isDirectory: true)
    }

    /// Write a single probe result (atomic tmp+rename)
    public static func write(_ result: ProbeResult) {
        let dir = probesDir
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let url = dir.appendingPathComponent("\(result.probeId).json")
        let tmp = dir.appendingPathComponent(".\(result.probeId).tmp")
        do {
            let data = try JSONEncoder.irisEncoder.encode(result)
            try data.write(to: tmp, options: .atomic)
            try? FileManager.default.removeItem(at: url)
            try FileManager.default.moveItem(at: tmp, to: url)
        } catch {
            logger.error("Failed to write probe result \(result.probeId): \(error)")
        }
    }

    /// Write the combined summary of all probe results
    public static func writeSummary(_ results: [ProbeResult]) {
        let dir = probesDir
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let url = dir.appendingPathComponent("latest.json")
        let tmp = dir.appendingPathComponent(".latest.tmp")
        do {
            let data = try JSONEncoder.irisEncoder.encode(results)
            try data.write(to: tmp, options: .atomic)
            try? FileManager.default.removeItem(at: url)
            try FileManager.default.moveItem(at: tmp, to: url)
        } catch {
            logger.error("Failed to write probe summary: \(error)")
        }
    }

    /// Read latest results (returns empty if none)
    public static func readLatest() -> [ProbeResult] {
        let url = probesDir.appendingPathComponent("latest.json")
        guard let data = try? Data(contentsOf: url) else { return [] }
        return (try? JSONDecoder.irisDecoder.decode([ProbeResult].self, from: data)) ?? []
    }

    /// Read a single probe's last result
    public static func readResult(probeId: String) -> ProbeResult? {
        let url = probesDir.appendingPathComponent("\(probeId).json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder.irisDecoder.decode(ProbeResult.self, from: data)
    }
}

// MARK: - JSON Coders

private extension JSONEncoder {
    static let irisEncoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }()
}

private extension JSONDecoder {
    static let irisDecoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}
