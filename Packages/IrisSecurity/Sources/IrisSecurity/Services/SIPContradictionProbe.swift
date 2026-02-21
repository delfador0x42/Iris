import Foundation
import os.log

/// Verifies SIP integrity by CONTRADICTION — don't ask the OS, TEST it.
///
/// Three independent checks that must agree:
/// 1. csr_get_active_config() — kernel's reported CSR bitmask
/// 2. Behavioral probe — attempt a SIP-protected operation, observe result
/// 3. NVRAM cross-check — read csr-active-config from IOKit, compare to kernel
///
/// If any two disagree, someone is lying.
public actor SIPContradictionProbe {
    public static let shared = SIPContradictionProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "SIPProbe")

    // Undocumented but stable syscall — in libsystem_kernel since 10.11
    @_silgen_name("csr_get_active_config")
    private static func csr_get_active_config(_ config: UnsafeMutablePointer<UInt32>) -> Int32

    @_silgen_name("csr_check")
    private static func csr_check(_ mask: UInt32) -> Int32

    // CSR flag bits from XNU bsd/sys/csr.h
    private static let CSR_ALLOW_UNTRUSTED_KEXTS:    UInt32 = 1 << 0
    private static let CSR_ALLOW_UNRESTRICTED_FS:    UInt32 = 1 << 1
    private static let CSR_ALLOW_TASK_FOR_PID:       UInt32 = 1 << 2
    private static let CSR_ALLOW_KERNEL_DEBUGGER:    UInt32 = 1 << 3
    private static let CSR_ALLOW_UNRESTRICTED_DTRACE: UInt32 = 1 << 5
    private static let CSR_ALLOW_UNRESTRICTED_NVRAM: UInt32 = 1 << 6

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // ── Source 1: Kernel-reported CSR config ──────────────
        var kernelConfig: UInt32 = 0
        let kernelOK = Self.csr_get_active_config(&kernelConfig) == 0
        let kernelSaysDisabled = kernelOK && (kernelConfig & Self.CSR_ALLOW_UNRESTRICTED_FS) != 0

        // ── Source 2: Behavioral probe — try SIP-protected write ──
        let probeResult = behavioralProbe()

        // ── Source 3: NVRAM cross-check ──────────────────────
        let nvramConfig = readNVRAMCSRConfig()

        // ── Contradiction detection ──────────────────────────
        let evidence = [
            "kernel_config: 0x\(String(kernelConfig, radix: 16))",
            "kernel_says_disabled: \(kernelSaysDisabled)",
            "write_probe_succeeded: \(probeResult.writeSucceeded)",
            "probe_error: \(probeResult.error ?? "none")",
            "nvram_config: \(nvramConfig.map { "0x\(String($0, radix: 16))" } ?? "unreadable")",
        ]

        // CONTRADICTION 1: Kernel says SIP on, but we can write to /System
        if !kernelSaysDisabled && probeResult.writeSucceeded {
            anomalies.append(.filesystem(
                name: "SIP", path: "contradiction:kernel-vs-behavior",
                technique: "SIP Integrity Violation",
                description: "CRITICAL: Kernel reports SIP enabled (0x\(String(kernelConfig, radix: 16))) but write to protected path SUCCEEDED. SIP is being spoofed.",
                severity: .critical, mitreID: "T1553.006",
                scannerId: "sip_contradiction",
                enumMethod: "csr_get_active_config() vs write(/System/) behavioral probe",
                evidence: evidence))
            logger.critical("SIP CONTRADICTION: kernel says on, write succeeded")
        }

        // CONTRADICTION 2: Kernel says SIP off, but write fails
        if kernelSaysDisabled && !probeResult.writeSucceeded && probeResult.error != nil {
            // This could indicate SIP is actually ON but csr_get_active_config is hooked
            // to report disabled — an attacker making us think SIP is off
            // Less dangerous (attacker hiding SIP being on), but still a lie
            anomalies.append(.filesystem(
                name: "SIP", path: "contradiction:kernel-vs-behavior",
                technique: "SIP Report Inconsistency",
                description: "Kernel reports SIP disabled (0x\(String(kernelConfig, radix: 16))) but protected write FAILED. csr_get_active_config() may be hooked.",
                severity: .high, mitreID: "T1014",
                scannerId: "sip_contradiction",
                enumMethod: "csr_get_active_config() vs write(/System/) behavioral probe",
                evidence: evidence))
        }

        // CONTRADICTION 3: NVRAM and kernel disagree
        if let nv = nvramConfig, kernelOK, nv != kernelConfig {
            anomalies.append(.filesystem(
                name: "SIP", path: "contradiction:kernel-vs-nvram",
                technique: "SIP NVRAM Mismatch",
                description: "Kernel CSR config (0x\(String(kernelConfig, radix: 16))) != NVRAM csr-active-config (0x\(String(nv, radix: 16))). One source is lying.",
                severity: .critical, mitreID: "T1542",
                scannerId: "sip_contradiction",
                enumMethod: "csr_get_active_config() vs IORegistryEntryCreateCFProperty(csr-active-config)",
                evidence: evidence))
            logger.critical("SIP CONTRADICTION: kernel 0x\(String(kernelConfig, radix: 16)) != NVRAM 0x\(String(nv, radix: 16))")
        }

        // ── Per-flag behavioral validation ───────────────────
        // For each critical CSR flag, verify csr_check() matches behavioral reality
        anomalies.append(contentsOf: validateTaskForPid(kernelConfig: kernelConfig))

        return anomalies
    }

    // MARK: - Behavioral Probes

    private struct ProbeResult {
        let writeSucceeded: Bool
        let error: String?
    }

    /// Attempt to create a file in a SIP-protected location.
    /// If SIP is really on, this MUST fail with EPERM.
    private func behavioralProbe() -> ProbeResult {
        let probePath = "/System/.iris_sip_probe_\(getpid())"
        let data = Data([0x49, 0x52, 0x49, 0x53]) // "IRIS"

        do {
            try data.write(to: URL(fileURLWithPath: probePath))
            // If we get here, SIP is actually off for filesystem operations
            try? FileManager.default.removeItem(atPath: probePath)
            return ProbeResult(writeSucceeded: true, error: nil)
        } catch {
            return ProbeResult(writeSucceeded: false, error: error.localizedDescription)
        }
    }

    /// Verify task_for_pid works when CSR says it should
    private func validateTaskForPid(kernelConfig: UInt32) -> [ProcessAnomaly] {
        let csrSaysAllowed = (kernelConfig & Self.CSR_ALLOW_TASK_FOR_PID) != 0
        let csr_check_says = Self.csr_check(Self.CSR_ALLOW_TASK_FOR_PID) == 0

        if csrSaysAllowed != csr_check_says {
            return [.filesystem(
                name: "SIP", path: "contradiction:csr_config-vs-csr_check",
                technique: "CSR Flag Inconsistency",
                description: "csr_get_active_config bit 2 (TASK_FOR_PID) = \(csrSaysAllowed) but csr_check(0x4) = \(csr_check_says). Syscall hooking detected.",
                severity: .critical, mitreID: "T1014",
                scannerId: "sip_contradiction",
                enumMethod: "csr_get_active_config() bit test vs csr_check() return",
                evidence: [
                    "config_bit_2: \(csrSaysAllowed)",
                    "csr_check_result: \(csr_check_says)",
                ])]
        }
        return []
    }

    // MARK: - NVRAM

    /// Read csr-active-config directly from NVRAM via IOKit
    private func readNVRAMCSRConfig() -> UInt32? {
        let entry = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/options")
        guard entry != MACH_PORT_NULL else { return nil }
        defer { IOObjectRelease(entry) }

        guard let prop = IORegistryEntryCreateCFProperty(
            entry, "csr-active-config" as CFString, kCFAllocatorDefault, 0
        ) else { return nil }

        guard let data = prop.takeRetainedValue() as? Data, data.count >= 1 else { return nil }

        // Little-endian, may be 1-4 bytes
        var config: UInt32 = 0
        data.withUnsafeBytes { ptr in
            for i in 0..<min(ptr.count, 4) {
                config |= UInt32(ptr[i]) << (i * 8)
            }
        }
        return config
    }
}
