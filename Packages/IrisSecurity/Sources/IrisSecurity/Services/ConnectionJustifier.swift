import Foundation

// MARK: - Connection Justification

/// Complete justification for a network connection — answers "WHY is this happening?"
public struct ConnectionJustification: Identifiable, Sendable {
    public let id: UUID
    public let connectionId: UUID
    public let timestamp: Date

    public let processName: String
    public let processInfo: ProcessKnowledgeBase.Info?
    public let destination: String
    public let destinationInfo: ProcessKnowledgeBase.DestinationInfo?

    public let verdict: ConnectionVerdict
    public let reasons: [JustificationReason]
    public let riskScore: Double  // 0.0 (safe) to 1.0 (dangerous)
    public let summary: String

    public var isExpected: Bool { verdict == .expected || verdict == .normal }
}

public enum ConnectionVerdict: String, Sendable, Codable {
    case expected = "Expected"
    case normal = "Normal"
    case telemetry = "Telemetry"
    case unusual = "Unusual"
    case suspicious = "Suspicious"
    case dangerous = "Dangerous"
    case unknown = "Unknown"
}

public struct JustificationReason: Sendable {
    public let factor: String
    public let detail: String
    public let weight: Double  // negative = safe, positive = risky
    public var isPositive: Bool { weight <= 0 }
}

// MARK: - Engine

/// Explains WHY each network connection exists.
public actor ConnectionJustifier {

    public static let shared = ConnectionJustifier()
    private var cache: [UUID: ConnectionJustification] = [:]

    private init() {}

    public func justify(
        connectionId: UUID,
        processName: String,
        processPath: String,
        isAppleSigned: Bool,
        remoteHost: String,
        remoteAddress: String,
        remotePort: UInt16,
        protocolName: String,
        bytesUp: UInt64 = 0,
        bytesDown: UInt64 = 0,
        remoteCountry: String? = nil,
        abuseScore: Int? = nil,
        isTor: Bool = false,
        isKnownScanner: Bool = false,
        httpMethod: String? = nil
    ) -> ConnectionJustification {
        if let cached = cache[connectionId] { return cached }

        var reasons: [JustificationReason] = []
        let procInfo = ProcessKnowledgeBase.lookup(processName)
            ?? ProcessKnowledgeBase.lookup(path: processPath)
        let host = remoteHost.isEmpty ? remoteAddress : remoteHost
        let destInfo = ProcessKnowledgeBase.lookupDestination(host)

        // ── Process Identity ───────────────────────────────────

        if let pk = procInfo {
            reasons.append(JustificationReason(
                factor: "Known Process",
                detail: "\(processName): \(pk.description)",
                weight: -0.3))

            if pk.isSystemCritical {
                reasons.append(JustificationReason(
                    factor: "System Critical",
                    detail: "Required macOS component",
                    weight: -0.2))
            }
        } else {
            reasons.append(JustificationReason(
                factor: "Unknown Process",
                detail: "No knowledge base entry for '\(processName)'",
                weight: 0.2))
        }

        if isAppleSigned {
            reasons.append(JustificationReason(
                factor: "Apple Signed",
                detail: "Valid Apple code signature",
                weight: -0.2))
        } else if !processPath.hasPrefix("/Applications/") && !processPath.hasPrefix("/opt/homebrew/") {
            reasons.append(JustificationReason(
                factor: "Unsigned + Non-Standard Path",
                detail: "Unsigned binary at \(processPath)",
                weight: 0.4))
        }

        // ── Destination Analysis ───────────────────────────────

        if let dk = destInfo {
            reasons.append(JustificationReason(
                factor: "Known Destination",
                detail: "\(dk.owner) — \(dk.purpose)",
                weight: dk.isTelemetry ? 0.1 : -0.2))

            if dk.isEssential {
                reasons.append(JustificationReason(
                    factor: "Essential Service",
                    detail: "Blocking would break system functionality",
                    weight: -0.3))
            }
        } else if Self.isPrivateAddress(remoteAddress) {
            reasons.append(JustificationReason(
                factor: "Local Network",
                detail: "Private/local address \(remoteAddress)",
                weight: -0.1))
        } else {
            reasons.append(JustificationReason(
                factor: "Unknown Destination",
                detail: "No knowledge for '\(host)'",
                weight: 0.2))
        }

        // ── Expected Connection Check ──────────────────────────

        if let pk = procInfo, !pk.expectedConnections.isEmpty {
            if ProcessKnowledgeBase.isExpectedConnection(processName, host: host) {
                reasons.append(JustificationReason(
                    factor: "Expected Connection",
                    detail: "\(processName) is known to connect to \(host)",
                    weight: -0.3))
            } else {
                reasons.append(JustificationReason(
                    factor: "Unexpected Connection",
                    detail: "\(processName) doesn't normally connect to \(host)",
                    weight: 0.3))
            }
        }

        // ── Port Analysis ──────────────────────────────────────

        let commonPorts: Set<UInt16> = [80, 443, 53, 993, 587, 465, 143, 25, 8080, 8443]
        if !commonPorts.contains(remotePort) && remotePort > 1024 {
            reasons.append(JustificationReason(
                factor: "Non-Standard Port",
                detail: "Port \(remotePort)",
                weight: 0.15))
        }

        // ── Threat Intelligence ────────────────────────────────

        if isTor {
            reasons.append(JustificationReason(
                factor: "Tor Exit Node",
                detail: "Known Tor exit node",
                weight: 0.7))
        }

        if isKnownScanner {
            reasons.append(JustificationReason(
                factor: "Known Scanner",
                detail: "Known internet scanner",
                weight: 0.3))
        }

        if let abuse = abuseScore, abuse > 50 {
            reasons.append(JustificationReason(
                factor: "High Abuse Score",
                detail: "AbuseIPDB: \(abuse)%",
                weight: Double(abuse) / 100.0))
        }

        // ── Geographic Analysis ────────────────────────────────

        if let country = remoteCountry {
            let highRisk: Set<String> = ["CN", "RU", "KP", "IR"]
            if highRisk.contains(country) {
                reasons.append(JustificationReason(
                    factor: "High-Risk Country",
                    detail: "Connection to \(country)",
                    weight: 0.3))
            }
        }

        // ── HTTP / Transfer Analysis ───────────────────────────

        if let method = httpMethod, method == "POST" || method == "PUT" {
            reasons.append(JustificationReason(
                factor: "Data Upload",
                detail: "\(method) to \(host)",
                weight: 0.1))
        }

        if bytesUp > 1_000_000 && bytesUp > bytesDown * 10 {
            reasons.append(JustificationReason(
                factor: "Heavy Upload",
                detail: "\(Self.formatBytes(bytesUp)) up — possible exfiltration",
                weight: 0.4))
        }

        // ── Suspicious Path ────────────────────────────────────

        let suspPaths = ["/tmp/", "/var/tmp/", "/Users/Shared/", "/.Trash/"]
        if suspPaths.contains(where: { processPath.hasPrefix($0) }) {
            reasons.append(JustificationReason(
                factor: "Suspicious Location",
                detail: "Process in temp/shared directory",
                weight: 0.5))
        }

        // ── Verdict ────────────────────────────────────────────

        let riskScore = Self.computeRisk(reasons)
        let verdict = Self.computeVerdict(riskScore: riskScore, reasons: reasons, destInfo: destInfo)
        let summary = Self.buildSummary(
            processName: processName, host: host, verdict: verdict,
            procInfo: procInfo, destInfo: destInfo, reasons: reasons)

        let justification = ConnectionJustification(
            id: UUID(), connectionId: connectionId, timestamp: Date(),
            processName: processName, processInfo: procInfo,
            destination: host, destinationInfo: destInfo,
            verdict: verdict, reasons: reasons,
            riskScore: riskScore, summary: summary)

        cache[connectionId] = justification
        if cache.count > 10_000 { pruneCache() }
        return justification
    }

    public func clearCache() { cache.removeAll() }

    // MARK: - Private

    private static func computeRisk(_ reasons: [JustificationReason]) -> Double {
        min(1.0, max(0.0, reasons.reduce(0.0) { $0 + max(0, $1.weight) }))
    }

    private static func computeVerdict(
        riskScore: Double, reasons: [JustificationReason],
        destInfo: ProcessKnowledgeBase.DestinationInfo?
    ) -> ConnectionVerdict {
        if riskScore >= 0.7 { return .dangerous }
        if riskScore >= 0.4 { return .suspicious }
        if let dk = destInfo, dk.isTelemetry { return .telemetry }
        if reasons.contains(where: { $0.factor == "Expected Connection" }) { return .expected }
        if riskScore < 0.15 { return .normal }
        if riskScore < 0.3 { return .unusual }
        return .unknown
    }

    private static func buildSummary(
        processName: String, host: String, verdict: ConnectionVerdict,
        procInfo: ProcessKnowledgeBase.Info?,
        destInfo: ProcessKnowledgeBase.DestinationInfo?,
        reasons: [JustificationReason]
    ) -> String {
        switch verdict {
        case .expected:
            return destInfo.map { "\(processName) → \($0.owner): \($0.purpose)" }
                ?? "\(processName) → \(host): expected"
        case .normal:
            return destInfo.map { "\(host) (\($0.owner)) — \($0.purpose)" }
                ?? "\(host) — normal traffic"
        case .telemetry:
            return "\(host) — telemetry (\(destInfo?.owner ?? "unknown"))"
        case .unusual:
            let detail = reasons.first { $0.weight > 0 }?.detail ?? "unexpected pattern"
            return "\(processName) → \(host): \(detail)"
        case .suspicious:
            let top = reasons.filter { $0.weight > 0 }.max(by: { $0.weight < $1.weight })
            return "\(processName) → \(host): \(top?.detail ?? "risk factors")"
        case .dangerous:
            let risks = reasons.filter { $0.weight >= 0.5 }.map(\.factor).joined(separator: ", ")
            return "\(processName) → \(host): DANGER — \(risks)"
        case .unknown:
            return "\(processName) → \(host): insufficient data"
        }
    }

    private static func isPrivateAddress(_ addr: String) -> Bool {
        addr.hasPrefix("10.") || addr.hasPrefix("192.168.") ||
        addr.hasPrefix("172.16.") || addr.hasPrefix("172.17.") ||
        addr.hasPrefix("172.18.") || addr.hasPrefix("172.19.") ||
        addr.hasPrefix("172.2") || addr.hasPrefix("172.3") ||
        addr == "127.0.0.1" || addr == "::1" || addr.hasPrefix("fe80:")
    }

    private static func formatBytes(_ bytes: UInt64) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        if bytes < 1_048_576 { return "\(bytes / 1024) KB" }
        if bytes < 1_073_741_824 { return "\(bytes / 1_048_576) MB" }
        return String(format: "%.1f GB", Double(bytes) / 1_073_741_824)
    }

    private func pruneCache() {
        let sorted = cache.sorted { $0.value.timestamp > $1.value.timestamp }
        cache = Dictionary(uniqueKeysWithValues: Array(sorted.prefix(5000)))
    }
}
