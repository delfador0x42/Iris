import Foundation
import os.log

/// Verifies SIP integrity by CONTRADICTION — don't ask the OS, TEST it.
///
/// Four independent sources that must agree:
/// 1. csr_get_active_config() — kernel's reported CSR bitmask
/// 2. csr_check() — per-flag behavioral query
/// 3. Behavioral probe — attempt a SIP-protected write, observe result
/// 4. NVRAM cross-check — read csr-active-config from IOKit
public actor SIPProbe: ContradictionProbe {
    public static let shared = SIPProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "SIPProbe")

    @_silgen_name("csr_get_active_config")
    private static func csr_get_active_config(_ config: UnsafeMutablePointer<UInt32>) -> Int32

    @_silgen_name("csr_check")
    private static func csr_check(_ mask: UInt32) -> Int32

    private static let CSR_ALLOW_UNRESTRICTED_FS: UInt32 = 1 << 1
    private static let CSR_ALLOW_TASK_FOR_PID:    UInt32 = 1 << 2

    public nonisolated let id = "sip-status"
    public nonisolated let name = "SIP Integrity"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "SIP status is what the kernel reports via csr_get_active_config()",
        groundTruth: "Four sources: csr_get_active_config() bitmask, csr_check() per-flag, behavioral write to /System, NVRAM csr-active-config via IOKit",
        adversaryCost: "Must hook csr_get_active_config AND csr_check AND intercept file writes AND fake NVRAM — 4 independent interception points",
        positiveDetection: "Shows exact disagreement: which source says what, hex config values",
        falsePositiveRate: "Near zero — SIP state is deterministic, only changes via csrutil in recovery"
    )

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        // Source 1: Kernel config
        var kernelConfig: UInt32 = 0
        let kernelOK = Self.csr_get_active_config(&kernelConfig) == 0
        let kernelSaysDisabled = kernelOK && (kernelConfig & Self.CSR_ALLOW_UNRESTRICTED_FS) != 0

        // Source 2: Behavioral probe
        let writeSucceeded = behavioralProbe()

        // Source 3: NVRAM
        let nvramConfig = readNVRAMCSRConfig()

        // Source 4: csr_check per-flag
        let csrCheckSaysTaskForPidAllowed = Self.csr_check(Self.CSR_ALLOW_TASK_FOR_PID) == 0
        let configSaysTaskForPidAllowed = (kernelConfig & Self.CSR_ALLOW_TASK_FOR_PID) != 0

        // Comparison 1: kernel config vs behavioral write
        if kernelOK {
            let match = kernelSaysDisabled == writeSucceeded
            if !match { hasContradiction = true }
            comparisons.append(SourceComparison(
                label: "kernel CSR config vs write(/System/) probe",
                sourceA: SourceValue("csr_get_active_config()", "0x\(String(kernelConfig, radix: 16)) (FS \(kernelSaysDisabled ? "disabled" : "enabled"))"),
                sourceB: SourceValue("/System write probe", writeSucceeded ? "write succeeded (SIP off)" : "write blocked (SIP on)"),
                matches: match))
        }

        // Comparison 2: kernel config vs NVRAM
        if kernelOK, let nv = nvramConfig {
            let match = kernelConfig == nv
            if !match { hasContradiction = true }
            comparisons.append(SourceComparison(
                label: "kernel CSR config vs NVRAM csr-active-config",
                sourceA: SourceValue("csr_get_active_config()", "0x\(String(kernelConfig, radix: 16))"),
                sourceB: SourceValue("IOKit NVRAM", "0x\(String(nv, radix: 16))"),
                matches: match))
        }

        // Comparison 3: csr_get_active_config bit vs csr_check
        if kernelOK {
            let match = configSaysTaskForPidAllowed == csrCheckSaysTaskForPidAllowed
            if !match { hasContradiction = true }
            comparisons.append(SourceComparison(
                label: "csr_get_active_config(TASK_FOR_PID) vs csr_check(0x4)",
                sourceA: SourceValue("config bit 2", configSaysTaskForPidAllowed ? "allowed" : "denied"),
                sourceB: SourceValue("csr_check(0x4)", csrCheckSaysTaskForPidAllowed ? "allowed" : "denied"),
                matches: match))
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        let verdict: ProbeVerdict
        let message: String

        if comparisons.isEmpty {
            verdict = .degraded
            message = "Could not read CSR config"
        } else if hasContradiction {
            verdict = .contradiction
            let mismatches = comparisons.filter { !$0.matches }
            message = "CONTRADICTION: \(mismatches.count) SIP source disagreement(s) — possible syscall hooking or NVRAM tampering"
            logger.critical("SIP CONTRADICTION: \(mismatches.count) mismatches")
        } else {
            verdict = .consistent
            message = "All \(comparisons.count) SIP sources agree"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    // MARK: - Sources

    private func behavioralProbe() -> Bool {
        let path = "/System/.iris_sip_probe_\(getpid())"
        let data = Data([0x49, 0x52, 0x49, 0x53])
        do {
            try data.write(to: URL(fileURLWithPath: path))
            try? FileManager.default.removeItem(atPath: path)
            return true
        } catch {
            return false
        }
    }

    private func readNVRAMCSRConfig() -> UInt32? {
        let entry = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/options")
        guard entry != MACH_PORT_NULL else { return nil }
        defer { IOObjectRelease(entry) }
        guard let prop = IORegistryEntryCreateCFProperty(
            entry, "csr-active-config" as CFString, kCFAllocatorDefault, 0
        ) else { return nil }
        guard let data = prop.takeRetainedValue() as? Data, data.count >= 1 else { return nil }
        var config: UInt32 = 0
        data.withUnsafeBytes { ptr in
            for i in 0..<min(ptr.count, 4) {
                config |= UInt32(ptr[i]) << (i * 8)
            }
        }
        return config
    }
}
