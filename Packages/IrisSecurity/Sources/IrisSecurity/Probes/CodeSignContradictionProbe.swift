import Foundation
import os.log

/// Cross-validates code signing state from 2 independent sources per binary:
///   Source 1: csops() kernel flags (CS_VALID, CS_DEBUGGED, CS_PLATFORM_BINARY)
///   Source 2: SecStaticCode validation (userspace code signing API)
///
/// Key signals:
///   CS_DEBUGGED on a system daemon → debugger attached, injection likely
///   CS_VALID=0 on running binary → signature was invalidated post-launch
///   Kernel says signed, SecStaticCode says invalid → runtime tampering
public actor CodeSignContradictionProbe: ContradictionProbe {
    public static let shared = CodeSignContradictionProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "CodeSignProbe")

    // csops constants (sys/codesign.h)
    private static let CS_OPS_STATUS: UInt32 = 0
    private static let CS_VALID: UInt32          = 0x00000001
    private static let CS_HARD: UInt32           = 0x00000100
    private static let CS_KILL: UInt32           = 0x00000200
    private static let CS_RUNTIME: UInt32        = 0x00010000
    private static let CS_SIGNED: UInt32         = 0x00020000
    private static let CS_PLATFORM_BINARY: UInt32 = 0x04000000
    private static let CS_DEBUGGED: UInt32       = 0x10000000

    public nonisolated let id = "codesign-contradiction"
    public nonisolated let name = "Code Signing Cross-Validation"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "Running processes have valid, untampered code signatures",
        groundTruth: "csops() reads kernel-level CS flags directly; SecStaticCode validates disk binary independently",
        adversaryCost: "Must hook csops syscall AND patch SecStaticCode evaluation — two different subsystems",
        positiveDetection: "Shows CS flags (DEBUGGED, VALID, PLATFORM) per binary with any kernel/userspace disagreement",
        falsePositiveRate: "Low — CS flags are immutable except via debugger attach or kernel exploit"
    )

    private let criticalProcesses: [(name: String, path: String)] = [
        ("launchd", "/sbin/launchd"),
        ("trustd", "/usr/libexec/trustd"),
        ("amfid", "/usr/libexec/amfid"),
        ("syspolicyd", "/usr/libexec/syspolicyd"),
        ("securityd", "/usr/libexec/securityd"),
        ("sshd", "/usr/sbin/sshd"),
        ("opendirectoryd", "/usr/libexec/opendirectoryd"),
        ("logd", "/usr/libexec/logd"),
        ("configd", "/usr/libexec/configd"),
        ("mDNSResponder", "/usr/sbin/mDNSResponder"),
    ]

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        let snapshot = ProcessSnapshot.capture()

        for binary in criticalProcesses {
            guard let pid = snapshot.pids.first(where: {
                snapshot.name(for: $0) == binary.name || snapshot.path(for: $0) == binary.path
            }) else { continue }

            // Source 1: Kernel CS flags via csops()
            var flags: UInt32 = 0
            let kr = iris_csops(pid, Self.CS_OPS_STATUS, &flags, MemoryLayout<UInt32>.size)
            guard kr == 0 else { continue }

            let valid = (flags & Self.CS_VALID) != 0
            let debugged = (flags & Self.CS_DEBUGGED) != 0
            let platform = (flags & Self.CS_PLATFORM_BINARY) != 0
            let runtime = (flags & Self.CS_RUNTIME) != 0
            let signed = (flags & Self.CS_SIGNED) != 0

            // Check 1: CS_DEBUGGED should NEVER be set on system daemons
            if debugged {
                hasContradiction = true
                comparisons.append(SourceComparison(
                    label: "\(binary.name) CS_DEBUGGED",
                    sourceA: SourceValue("csops() kernel", "CS_DEBUGGED=1 (debugger attached)"),
                    sourceB: SourceValue("expected", "CS_DEBUGGED=0 (system daemon)"),
                    matches: false))
            }

            // Check 2: CS_VALID should always be set for running system binaries
            if !valid && signed {
                hasContradiction = true
                comparisons.append(SourceComparison(
                    label: "\(binary.name) CS_VALID",
                    sourceA: SourceValue("csops() kernel", "CS_VALID=0 (signature invalidated)"),
                    sourceB: SourceValue("expected", "CS_VALID=1 (valid signature)"),
                    matches: false))
            }

            // Check 3: Platform binaries should have CS_PLATFORM_BINARY
            if !platform {
                hasContradiction = true
                comparisons.append(SourceComparison(
                    label: "\(binary.name) CS_PLATFORM_BINARY",
                    sourceA: SourceValue("csops() kernel", "CS_PLATFORM_BINARY=0"),
                    sourceB: SourceValue("expected", "CS_PLATFORM_BINARY=1 (Apple system binary)"),
                    matches: false))
            }

            // Source 2: SecStaticCode validation (disk binary)
            let secValid = validateViaSecStaticCode(path: binary.path)

            // Check 4: Cross-validate kernel flags vs SecStaticCode
            if valid != secValid {
                hasContradiction = true
                comparisons.append(SourceComparison(
                    label: "\(binary.name) kernel vs SecStaticCode",
                    sourceA: SourceValue("csops() CS_VALID", valid ? "valid" : "invalid"),
                    sourceB: SourceValue("SecStaticCode", secValid ? "valid" : "invalid"),
                    matches: false))
            }

            // If all checks pass, record consistency
            if !debugged && valid && platform && valid == secValid {
                let flagStr = "V=\(valid ? 1 : 0) D=\(debugged ? 1 : 0) P=\(platform ? 1 : 0) R=\(runtime ? 1 : 0)"
                comparisons.append(SourceComparison(
                    label: "\(binary.name) CS flags",
                    sourceA: SourceValue("csops() kernel", flagStr),
                    sourceB: SourceValue("SecStaticCode", secValid ? "valid" : "invalid"),
                    matches: true))
            }
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        let verdict: ProbeVerdict
        let message: String

        if comparisons.isEmpty {
            verdict = .degraded
            message = "No critical processes found for code signing validation"
        } else if hasContradiction {
            let issues = comparisons.filter { !$0.matches }.count
            verdict = .contradiction
            message = "CONTRADICTION: \(issues) code signing anomaly(ies) — possible injection or signature tampering"
            logger.critical("CODE SIGNING CONTRADICTION: \(issues) issues found")
        } else {
            verdict = .consistent
            message = "\(comparisons.count) binaries verified — all CS flags consistent"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    private func validateViaSecStaticCode(path: String) -> Bool {
        let url = URL(fileURLWithPath: path) as CFURL
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &code) == errSecSuccess,
              let staticCode = code else { return false }
        return SecStaticCodeCheckValidity(staticCode, [], nil) == errSecSuccess
    }
}
