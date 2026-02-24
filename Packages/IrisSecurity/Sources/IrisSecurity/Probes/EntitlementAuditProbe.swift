import Foundation
import Security
import os.log

/// Audits entitlements across all running processes via csops(CS_OPS_ENTITLEMENTS_BLOB).
///
/// On a compromised system, attackers forge CS_PLATFORM_BINARY status or inject
/// com.apple.private.* entitlements into non-Apple processes to gain privileged API access.
///
/// Cross-references TWO independent channels:
///   Source 1: csops(CS_OPS_STATUS) — kernel CS flags (attacker-controlled if kernel compromised)
///   Source 2: SecStaticCode(anchor apple) — disk-based Apple signature (independent verification)
///   Source 3: csops(CS_OPS_ENTITLEMENTS_BLOB) — kernel-stored entitlement blob
///
/// If csops says CS_PLATFORM_BINARY but SecStaticCode says NOT Apple-signed = forged platform.
/// If entitlements contain com.apple.private.* but SecStaticCode says NOT Apple = stolen entitlement.
/// Detection value = cost of consistent forgery across independent channels.
public actor EntitlementAuditProbe: ContradictionProbe {
    public static let shared = EntitlementAuditProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "EntitlementAudit")

    private static let CS_OPS_STATUS: UInt32 = 0
    private static let CS_OPS_ENTITLEMENTS_BLOB: UInt32 = 7
    private static let CS_PLATFORM_BINARY: UInt32 = 0x04000000
    private static let ENTITLEMENTS_MAGIC: UInt32 = 0xfade7171

    public nonisolated let id = "entitlement-audit"
    public nonisolated let name = "Entitlement Audit"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "Only Apple system binaries carry private Apple entitlements and platform binary status",
        groundTruth: "csops(CS_OPS_STATUS) cross-referenced against SecStaticCode(anchor apple) disk verification",
        adversaryCost: "Must forge cs_blob in kernel AND hook Security.framework signature validation — requires both kernel and userspace exploits",
        positiveDetection: "CS_PLATFORM_BINARY set but SecStaticCode rejects 'anchor apple'; or com.apple.private.* entitlements on non-Apple-signed binary",
        falsePositiveRate: "Very low — SecStaticCode anchor apple check is definitive for disk-based signature"
    )

    private static let privatePrefixes = [
        "com.apple.private.",
        "com.apple.rootless.",
        "com.apple.system-task-ports",
    ]

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        let snapshot = ProcessSnapshot.capture()
        var forgedPlatform: [String] = []
        var privateAbuse: [String] = []

        for pid in snapshot.pids where pid > 0 {
            let path = snapshot.path(for: pid)
            guard !path.isEmpty else { continue }
            let name = snapshot.name(for: pid)

            // Source 1: kernel CS flags
            var flags: UInt32 = 0
            guard iris_csops(pid, Self.CS_OPS_STATUS, &flags, MemoryLayout<UInt32>.size) == 0
            else { continue }

            let isPlatform = (flags & Self.CS_PLATFORM_BINARY) != 0

            // Source 2: disk-based Apple signature — independent of kernel
            let isAppleSigned = verifyAppleSignedOnDisk(path)

            // CONTRADICTION: kernel says platform binary, disk says NOT Apple-signed
            if isPlatform && !isAppleSigned {
                forgedPlatform.append("\(name)(\(pid)):\(path)")
            }

            // Only audit entitlements on non-Apple-signed binaries.
            // Apple-signed binaries legitimately carry private entitlements.
            // Note: if SecStaticCode is also compromised, both channels agree on a lie —
            // but that requires both kernel + userspace exploit (higher adversary cost).
            guard !isAppleSigned else { continue }

            if let keys = extractEntitlementKeys(pid: pid) {
                let stolen = keys.filter { k in
                    Self.privatePrefixes.contains { k.hasPrefix($0) }
                }
                if !stolen.isEmpty {
                    privateAbuse.append(
                        "\(name)(\(pid)):\(stolen.prefix(2).joined(separator: ","))")
                }
            }
        }

        if !forgedPlatform.isEmpty { hasContradiction = true }
        comparisons.append(SourceComparison(
            label: "CS_PLATFORM_BINARY vs SecStaticCode(anchor apple)",
            sourceA: SourceValue("csops(CS_OPS_STATUS)",
                forgedPlatform.isEmpty ? "consistent"
                    : forgedPlatform.prefix(5).joined(separator: "; ")),
            sourceB: SourceValue("SecStaticCode(anchor apple)",
                forgedPlatform.isEmpty ? "consistent" : "MISMATCH"),
            matches: forgedPlatform.isEmpty))

        if !privateAbuse.isEmpty { hasContradiction = true }
        comparisons.append(SourceComparison(
            label: "com.apple.private.* on non-Apple-signed binaries",
            sourceA: SourceValue("csops(ENTITLEMENTS_BLOB)",
                privateAbuse.isEmpty ? "none"
                    : privateAbuse.prefix(5).joined(separator: "; ")),
            sourceB: SourceValue("SecStaticCode", "not Apple-signed"),
            matches: privateAbuse.isEmpty))

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        return ProbeResult(
            probeId: id, probeName: name,
            verdict: hasContradiction ? .contradiction : .consistent,
            comparisons: comparisons,
            message: hasContradiction
                ? "CONTRADICTION: \(forgedPlatform.count) forged platform, \(privateAbuse.count) private entitlement abuse"
                : "No forged platform binaries or private entitlement abuse",
            durationMs: durationMs)
    }

    // MARK: - SecStaticCode verification (disk-based, independent of kernel)

    /// Verify binary on disk is signed by Apple's root CA.
    /// This is independent of csops — reads the Mach-O directly and validates
    /// the code signature chain back to Apple's root certificate.
    private func verifyAppleSignedOnDisk(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let staticCode = code else { return false }

        var req: SecRequirement?
        // "anchor apple" = signed by Apple's root CA (not just Apple-distributed)
        guard SecRequirementCreateWithString("anchor apple" as CFString, [], &req) == errSecSuccess,
              let requirement = req else { return false }

        return SecStaticCodeCheckValidity(staticCode, [], requirement) == errSecSuccess
    }

    // MARK: - Entitlement extraction

    private func extractEntitlementKeys(pid: pid_t) -> [String]? {
        var buf = [UInt8](repeating: 0, count: 16384)
        let ret = buf.withUnsafeMutableBytes { ptr in
            iris_csops(pid, Self.CS_OPS_ENTITLEMENTS_BLOB, ptr.baseAddress, ptr.count)
        }
        guard ret == 0, buf.count >= 8 else { return nil }

        let magic = UInt32(buf[0]) << 24 | UInt32(buf[1]) << 16
            | UInt32(buf[2]) << 8 | UInt32(buf[3])
        guard magic == Self.ENTITLEMENTS_MAGIC else { return nil }

        let length = Int(
            UInt32(buf[4]) << 24 | UInt32(buf[5]) << 16
                | UInt32(buf[6]) << 8 | UInt32(buf[7]))
        guard length > 8, length <= buf.count else { return nil }

        let plistData = Data(buf[8..<length])
        guard let dict = try? PropertyListSerialization.propertyList(
            from: plistData, options: [], format: nil) as? [String: Any]
        else { return nil }
        return Array(dict.keys)
    }
}
