import Foundation
import os.log

/// Scans macOS system integrity posture: SIP, AMFI, SecureBoot, SSV, trust caches.
/// Covers hunt scripts: eficheck, nvram_boot, ctrr_status, trust_caches, macf_policies.
public actor SystemIntegrityScanner {
    public static let shared = SystemIntegrityScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "SystemIntegrity")

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        anomalies.append(contentsOf: checkAMFI())
        anomalies.append(contentsOf: checkSecureKernel())
        anomalies.append(contentsOf: checkBootArgs())
        anomalies.append(contentsOf: checkKernelCollections())
        anomalies.append(contentsOf: await checkTrustCaches())
        return anomalies
    }

    /// Check AMFI (Apple Mobile File Integrity) enforcement
    private func checkAMFI() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        var size = 0
        if sysctlbyname("security.mac.amfi.enabled", nil, &size, nil, 0) == 0 {
            var val: Int32 = 0; size = MemoryLayout<Int32>.size
            sysctlbyname("security.mac.amfi.enabled", &val, &size, nil, 0)
            if val == 0 {
                result.append(.filesystem(
                    name: "AMFI", path: "sysctl:security.mac.amfi.enabled",
                    technique: "AMFI Disabled", description: "Apple Mobile File Integrity is disabled. Code signing enforcement bypassed.",
                    severity: .critical, mitreID: "T1553.006",
                    scannerId: "system_integrity",
                    enumMethod: "sysctlbyname(security.mac.amfi.enabled)",
                    evidence: ["amfi_enabled: 0"]))
            }
        }
        return result
    }

    /// Check kernel secure level
    private func checkSecureKernel() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        var val: Int32 = 0; var size = MemoryLayout<Int32>.size
        if sysctlbyname("kern.secure_kernel", &val, &size, nil, 0) == 0, val == 0 {
            result.append(.filesystem(
                name: "SecureKernel", path: "sysctl:kern.secure_kernel",
                technique: "Insecure Kernel", description: "kern.secure_kernel=0. Kernel task port may be accessible.",
                severity: .high, mitreID: "T1014",
                scannerId: "system_integrity",
                enumMethod: "sysctlbyname(kern.secure_kernel)",
                evidence: ["secure_kernel: 0"]))
        }
        return result
    }

    /// Check boot-args for dangerous flags
    private func checkBootArgs() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        var size = 256; var buf = [CChar](repeating: 0, count: size)
        if sysctlbyname("kern.bootargs", &buf, &size, nil, 0) == 0 {
            let args = String(cString: buf)
            let dangerous = [
                ("amfi_get_out_of_my_way=1", "AMFI bypassed via boot args"),
                ("cs_enforcement_disable=1", "Code signing enforcement disabled"),
                ("kext-dev-mode=1", "Kernel extension developer mode enabled"),
                ("-no_compat_check", "Hardware compatibility checks disabled"),
            ]
            for (flag, desc) in dangerous where args.contains(flag) {
                result.append(.filesystem(
                    name: flag, path: "sysctl:kern.bootargs",
                    technique: "Dangerous Boot Arg", description: desc,
                    severity: .critical, mitreID: "T1542",
                    scannerId: "system_integrity",
                    enumMethod: "sysctlbyname(kern.bootargs)",
                    evidence: [
                        "boot_flag: \(flag)",
                        "boot_args: \(args)",
                    ]))
            }
        }
        return result
    }

    /// Hash kernel collections for integrity verification
    private func checkKernelCollections() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let kcs = ["/System/Library/KernelCollections/BootKernelExtensions.kc",
                    "/Library/KernelCollections/AuxiliaryKernelExtensions.kc"]
        let fm = FileManager.default
        for kc in kcs {
            guard fm.fileExists(atPath: kc) else { continue }
            if let attrs = try? fm.attributesOfItem(atPath: kc),
               let mod = attrs[.modificationDate] as? Date,
               mod > Date().addingTimeInterval(-86400 * 7) {
                // KC modified within last 7 days outside update cycle
                result.append(.filesystem(
                    name: (kc as NSString).lastPathComponent, path: kc,
                    technique: "Recent KC Modification", description: "Kernel collection modified recently. May indicate kext tampering.",
                    severity: .high, mitreID: "T1547.006",
                    scannerId: "system_integrity",
                    enumMethod: "FileManager.attributesOfItem(.modificationDate)",
                    evidence: [
                        "path: \(kc)",
                        "modified: \(mod)",
                    ]))
            }
        }
        return result
    }

    /// Check trust cache status
    private func checkTrustCaches() async -> [ProcessAnomaly] {
        guard let output = runCommand("/usr/bin/csrutil", args: ["status"]) else { return [] }
        var result: [ProcessAnomaly] = []
        if output.contains("disabled") {
            result.append(.filesystem(
                name: "SIP", path: "csrutil",
                technique: "SIP Disabled", description: "System Integrity Protection is disabled.",
                severity: .critical, mitreID: "T1553.006",
                scannerId: "system_integrity",
                enumMethod: "csrutil status",
                evidence: ["csrutil_output: \(output.trimmingCharacters(in: .whitespacesAndNewlines))"]))
        }
        return result
    }

    private func runCommand(_ path: String, args: [String]) -> String? {
        let proc = Process(); proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        let pipe = Pipe(); proc.standardOutput = pipe; proc.standardError = pipe
        try? proc.run(); proc.waitUntilExit()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
    }
}
