import Foundation
import os.log

/// Audits supply chain integrity: Homebrew packages, npm global modules,
/// pip packages, and Xcode plugins for tampering or suspicious modifications.
/// APT41 compromised Xcode. Lazarus trojanized crypto trading apps.
/// Supply chain is the modern attack vector.
public actor SupplyChainAuditor {
    public static let shared = SupplyChainAuditor()
    let logger = Logger(subsystem: "com.wudan.iris", category: "SupplyChain")

    /// Audit all package managers
    public func auditAll() async -> [SupplyChainFinding] {
        async let brew = auditHomebrew()
        async let npm = auditNPMGlobal()
        async let pip = auditPipPackages()
        async let xcode = auditXcodePlugins()

        let all = await [brew, npm, pip, xcode]
        return all.flatMap { $0 }
    }

    func runCommand(_ path: String, args: [String]) async -> String {
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

/// Source of a supply chain package
public enum PackageManagerSource: String, Sendable, Codable {
    case homebrew = "Homebrew"
    case npm = "npm"
    case pip = "pip"
    case xcode = "Xcode"
}

/// A supply chain integrity finding
public struct SupplyChainFinding: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let source: PackageManagerSource
    public let packageName: String
    public let finding: String
    public let details: String
    public let severity: AnomalySeverity
    public let timestamp: Date

    public init(
        id: UUID = UUID(),
        source: PackageManagerSource,
        packageName: String,
        finding: String,
        details: String,
        severity: AnomalySeverity,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.source = source
        self.packageName = packageName
        self.finding = finding
        self.details = details
        self.severity = severity
        self.timestamp = timestamp
    }
}
