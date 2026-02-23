import Foundation
import os.log

/// Probes the kernel's Mandatory Access Control policy table via __mac_syscall.
///
/// A clean macOS system has exactly 3 MAC policies: Sandbox, AMFI, Quarantine.
/// Any additional policy = rootkit injected a custom MAC module into the kernel.
/// Any missing policy = rootkit unloaded a standard protection.
///
/// Detection method: call __mac_syscall("PolicyName", 0, NULL) for each policy.
/// Error semantics reveal whether the policy is loaded:
///   EFAULT/EINVAL/ENOSYS → policy EXISTS (tried to use the null arg)
///   ENOENT(2) or errno 103 → policy NOT registered
public actor MACPolicyProbe: ContradictionProbe {
    public static let shared = MACPolicyProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "MACPolicyProbe")

    @_silgen_name("__mac_syscall")
    private static func __mac_syscall(
        _ policy: UnsafePointer<CChar>,
        _ call: Int32,
        _ arg: UnsafeMutableRawPointer?
    ) -> Int32

    public nonisolated let id = "mac-policy"
    public nonisolated let name = "MAC Policy Census"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "Only standard macOS security policies (Sandbox, AMFI, Quarantine) are loaded in the kernel",
        groundTruth: "__mac_syscall() directly queries the kernel MAC framework — error codes reveal loaded vs unloaded policies",
        adversaryCost: "Must intercept __mac_syscall or modify the kernel's mac_policy_list — requires persistent kernel access",
        positiveDetection: "Shows unexpected policy names (rootkit modules) or missing standard policies",
        falsePositiveRate: "Very low — MAC policy list changes only via kext load/unload, which is extremely rare on modern macOS"
    )

    /// Standard policies on a clean macOS system
    private static let expectedPolicies: Set<String> = ["Sandbox", "AMFI", "Quarantine"]

    /// Extended probe list: standard + known suspicious + common injection names
    private static let probeTargets: [String] = [
        // Expected (should be loaded)
        "Sandbox", "AMFI", "Quarantine",
        // Should NOT be loaded (known attack vectors)
        "TMSafetyNet", "endpointsecurity", "SEP",
        // Common rootkit/research MAC policy names
        "kauth_scope", "mac_none", "custom_mac", "rootkit",
        "stackshot", "AppleMobileFileIntegrity",
        // Kernel extensions that register MAC policies
        "ALF",  // Application Layer Firewall
    ]

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        var loaded: Set<String> = []
        var notLoaded: Set<String> = []

        for policy in Self.probeTargets {
            let isLoaded = probePolicy(policy)
            if isLoaded {
                loaded.insert(policy)
            } else {
                notLoaded.insert(policy)
            }
        }

        // Comparison 1: Are all expected policies present?
        let missingExpected = Self.expectedPolicies.subtracting(loaded)
        let allExpectedPresent = missingExpected.isEmpty
        if !allExpectedPresent { hasContradiction = true }
        comparisons.append(SourceComparison(
            label: "expected MAC policies present",
            sourceA: SourceValue("expected", Self.expectedPolicies.sorted().joined(separator: ", ")),
            sourceB: SourceValue("__mac_syscall", allExpectedPresent
                ? "all present"
                : "MISSING: \(missingExpected.sorted().joined(separator: ", "))"),
            matches: allExpectedPresent))

        // Comparison 2: Are there unexpected policies?
        let unexpected = loaded.subtracting(Self.expectedPolicies)
        let noUnexpected = unexpected.isEmpty
        if !noUnexpected { hasContradiction = true }
        comparisons.append(SourceComparison(
            label: "unexpected MAC policies",
            sourceA: SourceValue("loaded policies", loaded.sorted().joined(separator: ", ")),
            sourceB: SourceValue("expected (3 only)", Self.expectedPolicies.sorted().joined(separator: ", ")),
            matches: noUnexpected))

        // Comparison 3: Cross-check with sysctl security.mac
        let sysctlPolicies = readSysctlMACPolicies()
        if let sp = sysctlPolicies {
            // sysctl should list the same policies we found via __mac_syscall
            let sysctlSet = Set(sp.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) })
            let match = sysctlSet == loaded || sysctlSet.isSubset(of: loaded)
            if !match { hasContradiction = true }
            comparisons.append(SourceComparison(
                label: "sysctl security.mac vs __mac_syscall",
                sourceA: SourceValue("sysctl", sp),
                sourceB: SourceValue("__mac_syscall probing", loaded.sorted().joined(separator: ", ")),
                matches: match))
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        let verdict: ProbeVerdict
        let message: String

        if hasContradiction {
            verdict = .contradiction
            var reasons: [String] = []
            if !missingExpected.isEmpty {
                reasons.append("missing: \(missingExpected.sorted().joined(separator: ", "))")
            }
            if !unexpected.isEmpty {
                reasons.append("unexpected: \(unexpected.sorted().joined(separator: ", "))")
            }
            message = "CONTRADICTION: MAC policy anomaly — \(reasons.joined(separator: "; "))"
            logger.critical("MAC POLICY CONTRADICTION: \(reasons.joined(separator: "; "))")
        } else {
            verdict = .consistent
            message = "All 3 expected MAC policies present, no unexpected policies found"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    // MARK: - Probing

    /// Probe whether a MAC policy is loaded in the kernel.
    /// Returns true if the policy exists (any error except ENOENT/103).
    private func probePolicy(_ name: String) -> Bool {
        errno = 0
        let result = name.withCString { cstr in
            Self.__mac_syscall(cstr, 0, nil)
        }
        let e = errno
        // __mac_syscall returns -1 on error.
        // EFAULT(14), EINVAL(22), ENOSYS(78) → policy IS loaded (it tried to process our call)
        // ENOENT(2) or 103 → policy NOT registered in kernel
        if result == 0 {
            return true  // Succeeded — policy exists and handled our call
        }
        return e != 2 && e != 103
    }

    private func readSysctlMACPolicies() -> String? {
        var size = 0
        guard sysctlbyname("security.mac", nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname("security.mac", &buf, &size, nil, 0) == 0 else { return nil }
        return String(cString: buf)
    }
}
