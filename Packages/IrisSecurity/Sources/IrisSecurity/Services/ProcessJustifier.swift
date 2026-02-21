import Foundation

// MARK: - Process Justification

/// Complete justification for a running process — answers "WHY is this running?"
public struct ProcessJustification: Identifiable, Sendable {
    public let id: UUID
    public let pid: Int32
    public let processName: String
    public let processPath: String
    public let timestamp: Date

    public let knowledgeInfo: ProcessKnowledgeBase.Info?
    public let verdict: ProcessVerdict
    public let reasons: [ProcessReason]
    public let riskScore: Double
    public let summary: String
    public let explanation: String     // multi-line detailed explanation
    public let verification: String?   // how to verify this process is legitimate
}

public enum ProcessVerdict: String, Sendable, Codable {
    case systemCritical = "System Critical"   // kernel, launchd, WindowServer
    case systemService = "System Service"     // Apple daemon/agent
    case knownApplication = "Known App"       // recognized app
    case developerTool = "Dev Tool"           // build tools, editors
    case thirdParty = "Third Party"           // known but not Apple
    case suspicious = "Suspicious"            // risk factors present
    case dangerous = "Dangerous"              // multiple red flags
    case unknown = "Unknown"                  // not in knowledge base
}

public struct ProcessReason: Sendable {
    public let factor: String
    public let detail: String
    public let weight: Double  // negative = safe, positive = risky
    public var isPositive: Bool { weight <= 0 }
}

// MARK: - Justifier Engine

/// Explains WHY each process is running.
/// Combines static knowledge base with runtime code signing and behavioral analysis.
public actor ProcessJustifier {

    public static let shared = ProcessJustifier()
    private var cache: [String: ProcessJustification] = [:]  // keyed by "pid:path"

    private init() {}

    /// Justify a process. Cached by pid+path.
    public func justify(
        pid: Int32,
        processName: String,
        processPath: String,
        ppid: Int32 = 0,
        parentName: String = "",
        isAppleSigned: Bool = false,
        isPlatformBinary: Bool = false,
        teamId: String? = nil,
        signingId: String? = nil,
        isHardenedRuntime: Bool = false,
        userId: UInt32 = 0,
        cpuPercent: Double = 0,
        residentMemory: UInt64 = 0,
        threadCount: Int32 = 0,
        suspicionReasons: [String] = [],
        arguments: [String] = []
    ) -> ProcessJustification {
        let key = "\(pid):\(processPath)"
        if let cached = cache[key] { return cached }

        var reasons: [ProcessReason] = []
        let info = ProcessKnowledgeBase.lookup(processName)
            ?? ProcessKnowledgeBase.lookup(path: processPath)

        // ── Knowledge Base Match ───────────────────────────────

        if let k = info {
            reasons.append(ProcessReason(
                factor: "Known Process",
                detail: "\(processName): \(k.description)",
                weight: -0.3))

            if k.isSystemCritical {
                reasons.append(ProcessReason(
                    factor: "System Critical",
                    detail: "Required for macOS operation",
                    weight: -0.5))
            }
        } else {
            reasons.append(ProcessReason(
                factor: "Unknown Process",
                detail: "Not in knowledge base — manual review recommended",
                weight: 0.2))
        }

        // ── Code Signing Analysis ──────────────────────────────

        if isPlatformBinary {
            reasons.append(ProcessReason(
                factor: "Platform Binary",
                detail: "Apple platform binary — part of macOS",
                weight: -0.4))
        } else if isAppleSigned {
            reasons.append(ProcessReason(
                factor: "Apple Signed",
                detail: "Valid Apple code signature",
                weight: -0.3))
        } else if let team = teamId, !team.isEmpty {
            reasons.append(ProcessReason(
                factor: "Developer Signed",
                detail: "Signed by team \(team)",
                weight: -0.1))
        } else if let sid = signingId, sid.hasPrefix("com.apple.") {
            reasons.append(ProcessReason(
                factor: "Apple Signing ID",
                detail: "Claims Apple signing ID but not Apple-signed — possible impersonation",
                weight: 0.7))
        } else {
            reasons.append(ProcessReason(
                factor: "Unsigned",
                detail: "No valid code signature",
                weight: 0.3))
        }

        // Known system process running unsigned — tampering indicator
        if let k = info, k.isSystemCritical, !isAppleSigned, !isPlatformBinary {
            reasons.append(ProcessReason(
                factor: "Expected Signature Missing",
                detail: "\(processName) should be Apple-signed — possible replacement/tampering",
                weight: 0.6))
        }

        if isHardenedRuntime {
            reasons.append(ProcessReason(
                factor: "Hardened Runtime",
                detail: "Limited injection surface",
                weight: -0.1))
        }

        // ── Path Analysis ──────────────────────────────────────

        if processPath.hasPrefix("/System/") || processPath.hasPrefix("/usr/") {
            reasons.append(ProcessReason(
                factor: "System Path",
                detail: "Running from protected system location",
                weight: -0.2))
        } else if processPath.hasPrefix("/Applications/") {
            reasons.append(ProcessReason(
                factor: "Applications Path",
                detail: "Standard Applications directory",
                weight: -0.1))
        } else if processPath.hasPrefix("/opt/homebrew/") {
            reasons.append(ProcessReason(
                factor: "Homebrew Path",
                detail: "Installed via Homebrew",
                weight: -0.05))
        } else if processPath.hasPrefix("/tmp/") || processPath.hasPrefix("/var/tmp/") {
            reasons.append(ProcessReason(
                factor: "Temporary Directory",
                detail: "Running from temp — common malware staging location",
                weight: 0.5))
        } else if processPath.hasPrefix("/Users/Shared/") {
            reasons.append(ProcessReason(
                factor: "Shared Directory",
                detail: "Running from /Users/Shared — accessible to all users",
                weight: 0.3))
        } else if processPath.contains("/.") {
            reasons.append(ProcessReason(
                factor: "Hidden Path",
                detail: "Running from hidden directory — common evasion technique",
                weight: 0.4))
        }

        // ── Parent Process Analysis ────────────────────────────

        if !parentName.isEmpty {
            // Suspicious parent-child relationships
            let scriptLaunchers = ["osascript", "Terminal", "sh", "bash", "zsh"]
            if scriptLaunchers.contains(parentName) {
                if isPlatformBinary && processPath.hasPrefix("/System/") {
                    // System tool run from terminal — normal
                } else if !isAppleSigned {
                    reasons.append(ProcessReason(
                        factor: "Script-Spawned",
                        detail: "Unsigned process spawned by \(parentName)",
                        weight: 0.3))
                }
            }

            // launchd should be parent of most daemons
            if let k = info, k.isSystemCritical, parentName != "launchd", parentName != "kernel_task" {
                reasons.append(ProcessReason(
                    factor: "Unexpected Parent",
                    detail: "System-critical \(processName) has parent \(parentName) instead of launchd",
                    weight: 0.4))
            }
        }

        // ── User Analysis ──────────────────────────────────────

        if userId == 0 && !isPlatformBinary {
            let knownRootProcesses: Set<String> = [
                "launchd", "kernel_task", "syslogd", "securityd",
                "trustd", "mDNSResponder", "configd", "notifyd",
                "diskarbitrationd", "fseventsd", "kextd"
            ]
            if !knownRootProcesses.contains(processName) {
                reasons.append(ProcessReason(
                    factor: "Running as Root",
                    detail: "UID 0 without being a known system daemon",
                    weight: 0.3))
            }
        }

        // ── Resource Analysis ──────────────────────────────────

        if cpuPercent > 80 {
            reasons.append(ProcessReason(
                factor: "High CPU",
                detail: String(format: "Using %.0f%% CPU", cpuPercent),
                weight: 0.15))
        }

        if residentMemory > 500_000_000 { // > 500MB
            reasons.append(ProcessReason(
                factor: "High Memory",
                detail: "\(residentMemory / 1_048_576) MB resident",
                weight: 0.1))
        }

        // ── Argument Analysis ──────────────────────────────────

        let suspiciousArgs = ["-e", "curl ", "wget ", "base64", "/dev/tcp",
                              "bash -c", "python -c", "osascript -e"]
        for arg in arguments {
            if suspiciousArgs.contains(where: { arg.contains($0) }) {
                reasons.append(ProcessReason(
                    factor: "Suspicious Argument",
                    detail: "Argument contains: \(arg.prefix(60))",
                    weight: 0.3))
                break
            }
        }

        // ── Pre-existing Suspicion ─────────────────────────────

        for reason in suspicionReasons {
            if !reasons.contains(where: { $0.factor.lowercased().contains(reason.lowercased()) }) {
                reasons.append(ProcessReason(
                    factor: "Flagged: \(reason)",
                    detail: "Pre-identified suspicion factor",
                    weight: 0.2))
            }
        }

        // ── Compute Results ────────────────────────────────────

        let riskScore = Self.computeRisk(reasons)
        let verdict = Self.computeVerdict(
            riskScore: riskScore, info: info,
            isAppleSigned: isAppleSigned, isPlatformBinary: isPlatformBinary)
        let summary = Self.buildSummary(
            processName: processName, verdict: verdict, info: info)
        let explanation = Self.buildExplanation(
            processName: processName, processPath: processPath,
            info: info, reasons: reasons, verdict: verdict)
        let verification = Self.buildVerification(
            processName: processName, processPath: processPath,
            isPlatformBinary: isPlatformBinary)

        let justification = ProcessJustification(
            id: UUID(), pid: pid, processName: processName,
            processPath: processPath, timestamp: Date(),
            knowledgeInfo: info, verdict: verdict, reasons: reasons,
            riskScore: riskScore, summary: summary,
            explanation: explanation, verification: verification)

        cache[key] = justification
        if cache.count > 10_000 { pruneCache() }
        return justification
    }

    public func clearCache() { cache.removeAll() }

    // MARK: - Verdict Computation

    private static func computeRisk(_ reasons: [ProcessReason]) -> Double {
        let raw = reasons.reduce(0.0) { $0 + max(0, $1.weight) }
        return min(1.0, max(0.0, raw))
    }

    private static func computeVerdict(
        riskScore: Double, info: ProcessKnowledgeBase.Info?,
        isAppleSigned: Bool, isPlatformBinary: Bool
    ) -> ProcessVerdict {
        if riskScore >= 0.7 { return .dangerous }
        if riskScore >= 0.4 { return .suspicious }

        if let k = info {
            if k.isSystemCritical { return .systemCritical }
            switch k.category {
            case .kernel, .systemDaemon, .systemAgent, .systemService, .security, .network:
                return isAppleSigned || isPlatformBinary ? .systemService : .thirdParty
            case .devTool:
                return .developerTool
            case .userApp:
                return isAppleSigned ? .knownApplication : .thirdParty
            default:
                return isAppleSigned ? .systemService : .thirdParty
            }
        }

        return .unknown
    }

    // MARK: - Summary Generation

    private static func buildSummary(
        processName: String, verdict: ProcessVerdict,
        info: ProcessKnowledgeBase.Info?
    ) -> String {
        if let k = info {
            return "\(k.category.rawValue): \(k.description)"
        }
        return "\(verdict.rawValue): \(processName)"
    }

    private static func buildExplanation(
        processName: String, processPath: String,
        info: ProcessKnowledgeBase.Info?, reasons: [ProcessReason],
        verdict: ProcessVerdict
    ) -> String {
        var lines: [String] = []

        switch verdict {
        case .systemCritical:
            lines.append("\(processName) is a critical macOS system component.")
            if let k = info { lines.append(k.description) }
            lines.append("Terminating this process would cause system instability.")

        case .systemService:
            lines.append("\(processName) is a macOS system service.")
            if let k = info { lines.append(k.description) }

        case .knownApplication:
            lines.append("\(processName) is a recognized application.")
            if let k = info { lines.append(k.description) }

        case .developerTool:
            lines.append("\(processName) is a development tool.")
            if let k = info { lines.append(k.description) }

        case .thirdParty:
            lines.append("\(processName) is a third-party application.")
            if let k = info { lines.append(k.description) }

        case .suspicious:
            lines.append("\(processName) has suspicious characteristics:")
            for r in reasons where r.weight > 0.2 {
                lines.append("  \u{2022} \(r.factor): \(r.detail)")
            }

        case .dangerous:
            lines.append("\(processName) shows multiple danger indicators:")
            for r in reasons where r.weight > 0.3 {
                lines.append("  \u{2022} \(r.factor): \(r.detail)")
            }

        case .unknown:
            lines.append("\(processName) is not recognized.")
            lines.append("Path: \(processPath)")
            lines.append("Manual investigation recommended.")
        }

        return lines.joined(separator: "\n")
    }

    private static func buildVerification(
        processName: String, processPath: String,
        isPlatformBinary: Bool
    ) -> String? {
        var steps: [String] = []

        steps.append("codesign -dvvv \"\(processPath)\"")

        if isPlatformBinary {
            steps.append("# Platform binary — verified by kernel. Check SIP: csrutil status")
        }

        steps.append("ps -p $(pgrep -x \"\(processName)\") -o pid,ppid,user,%cpu,%mem,command")
        steps.append("lsof -p <pid> | head -20")
        steps.append("lsof -i -p <pid>")

        return steps.isEmpty ? nil : steps.joined(separator: "\n")
    }

    private func pruneCache() {
        let sorted = cache.sorted { $0.value.timestamp > $1.value.timestamp }
        cache = Dictionary(uniqueKeysWithValues: Array(sorted.prefix(5000)))
    }
}
