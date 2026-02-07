import Foundation
import os.log
import CryptoKit

/// Monitors TCC.db for unauthorized permission grants.
/// APTs modify TCC.db to silently grant themselves Full Disk Access,
/// Screen Recording, Accessibility, etc. This monitor detects those changes.
public actor TCCMonitor {
    public static let shared = TCCMonitor()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "TCCMonitor")

    /// Known TCC database locations
    private let tccPaths: [String] = {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return [
            "\(home)/Library/Application Support/com.apple.TCC/TCC.db",
            "/Library/Application Support/com.apple.TCC/TCC.db"
        ]
    }()

    /// Baseline hashes for TCC databases
    private var baselineHashes: [String: String] = [:]
    private var baselineEntries: [String: [TCCEntry]] = [:]

    /// High-risk services that APTs target
    private let highRiskServices: Set<String> = [
        "kTCCServiceSystemPolicyAllFiles",  // Full Disk Access
        "kTCCServiceScreenCapture",          // Screen Recording
        "kTCCServiceAccessibility",          // Accessibility (keystroke injection)
        "kTCCServiceListenEvent",            // Input Monitoring
        "kTCCServicePostEvent",              // Keystroke injection
        "kTCCServiceAppleEvents",            // Automation (script injection)
    ]

    /// Take a baseline snapshot of all TCC databases
    public func takeBaseline() async {
        for path in tccPaths {
            guard FileManager.default.fileExists(atPath: path) else { continue }
            if let hash = hashFile(path) {
                baselineHashes[path] = hash
            }
            let entries = await readTCCEntries(path: path)
            baselineEntries[path] = entries
            logger.info("TCC baseline: \(path) — \(entries.count) entries, hash: \(hash ?? "n/a")")
        }
    }

    /// Check if TCC databases have been modified since baseline
    public func checkIntegrity() async -> [TCCChange] {
        var changes: [TCCChange] = []

        for path in tccPaths {
            guard FileManager.default.fileExists(atPath: path) else { continue }
            let currentHash = hashFile(path)

            if let baseline = baselineHashes[path], let current = currentHash,
               baseline != current {
                // Database changed — diff entries
                let currentEntries = await readTCCEntries(path: path)
                let previousEntries = baselineEntries[path] ?? []

                let previousSet = Set(previousEntries.map { "\($0.service)|\($0.client)" })

                for entry in currentEntries {
                    let key = "\(entry.service)|\(entry.client)"
                    if !previousSet.contains(key) && entry.isAllowed {
                        let isHighRisk = highRiskServices.contains(entry.service)
                        changes.append(TCCChange(
                            path: path,
                            entry: entry,
                            changeType: .newGrant,
                            severity: isHighRisk ? .critical : .medium
                        ))
                    }
                }
            }
        }

        return changes
    }

    /// Read all TCC entries and flag suspicious ones
    public func scan() async -> [TCCEntry] {
        var allEntries: [TCCEntry] = []

        for path in tccPaths {
            let entries = await readTCCEntries(path: path)
            allEntries.append(contentsOf: entries)
        }

        return allEntries
    }

    /// Read TCC entries by running sqlite3 (we don't link SQLite directly)
    private func readTCCEntries(path: String) async -> [TCCEntry] {
        // Query the TCC database using sqlite3 CLI
        let query = "SELECT service, client, client_type, auth_value, auth_reason, indirect_object_identifier, last_modified FROM access;"
        let output = await runCommand("/usr/bin/sqlite3", args: ["-separator", "|", path, query])

        return output.split(separator: "\n").compactMap { line in
            let parts = line.split(separator: "|", omittingEmptySubsequences: false)
            guard parts.count >= 5 else { return nil }

            let service = String(parts[0])
            let client = String(parts[1])
            let clientType = Int(parts[2]) ?? 0
            let authValue = Int(parts[3]) ?? 0
            let authReason = Int(parts[4]) ?? 0
            let indirect = parts.count > 5 && !parts[5].isEmpty
            let lastMod: Date? = parts.count > 6 ? dateFromTimestamp(String(parts[6])) : nil

            // Determine suspicion
            var suspicious = false
            var reason: String?

            // Flag: high-risk service granted to unknown bundle
            if highRiskServices.contains(service) && authValue == 2 {
                // Check if client exists on disk
                if clientType == 0 {
                    // Bundle ID — check if app exists
                    let appPath = findAppPath(bundleID: client)
                    if appPath == nil {
                        suspicious = true
                        reason = "High-risk permission granted to non-existent app: \(client)"
                    }
                }
                // Flag if authReason is not user-initiated
                if authReason != 1 && authReason != 2 {
                    suspicious = true
                    reason = (reason ?? "") + " Permission granted via non-user mechanism (reason: \(authReason))"
                }
            }

            return TCCEntry(
                service: service,
                client: client,
                clientType: clientType,
                authValue: authValue,
                authReason: authReason,
                indirect: indirect,
                lastModified: lastMod,
                isSuspicious: suspicious,
                suspicionReason: reason
            )
        }
    }

    private func hashFile(_ path: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func dateFromTimestamp(_ str: String) -> Date? {
        guard let epoch = Double(str) else { return nil }
        // TCC uses Core Data timestamp (seconds since 2001-01-01)
        return Date(timeIntervalSinceReferenceDate: epoch)
    }

    private func findAppPath(bundleID: String) -> String? {
        // Check common locations
        let searchDirs = ["/Applications", "/System/Applications"]
        let fm = FileManager.default
        for dir in searchDirs {
            guard let apps = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for app in apps where app.hasSuffix(".app") {
                let plistPath = "\(dir)/\(app)/Contents/Info.plist"
                if let plist = NSDictionary(contentsOfFile: plistPath),
                   let bid = plist["CFBundleIdentifier"] as? String,
                   bid == bundleID {
                    return "\(dir)/\(app)"
                }
            }
        }
        return nil
    }

    private func runCommand(_ path: String, args: [String]) async -> String {
        await withCheckedContinuation { continuation in
            let process = Process()
            let pipe = Pipe()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = args
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                process.waitUntilExit()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
            } catch {
                continuation.resume(returning: "")
            }
        }
    }
}

/// A detected change to the TCC database
public struct TCCChange: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let path: String
    public let entry: TCCEntry
    public let changeType: ChangeType
    public let severity: AnomalySeverity
    public let timestamp: Date

    public enum ChangeType: String, Sendable, Codable {
        case newGrant = "New Permission Grant"
        case revoked = "Permission Revoked"
        case modified = "Permission Modified"
    }

    public init(
        id: UUID = UUID(),
        path: String,
        entry: TCCEntry,
        changeType: ChangeType,
        severity: AnomalySeverity,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.path = path
        self.entry = entry
        self.changeType = changeType
        self.severity = severity
        self.timestamp = timestamp
    }
}
