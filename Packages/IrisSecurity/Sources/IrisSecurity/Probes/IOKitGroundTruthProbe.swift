import Foundation
import IOKit
import os.log

/// Hardware identity baseline via IOKit registry.
/// Cross-checks IOPlatformExpertDevice properties against sysctl values.
///
/// Source 1: IOKit IOPlatformExpertDevice (UUID, serial, model, target-type)
/// Source 2: sysctl hw.model (kern.uuid is kernel boot UUID, NOT hardware UUID)
/// Source 3: NVRAM values (csr-active-config, boot-args) via IOKit
///
/// Detects: NVRAM tampering, platform identity spoofing, VM detection evasion.
public actor IOKitGroundTruthProbe: ContradictionProbe {
    public static let shared = IOKitGroundTruthProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "IOKitProbe")

    public nonisolated let id = "iokit-ground-truth"
    public nonisolated let name = "IOKit Hardware Identity"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "Hardware identity properties are consistent across IOKit and sysctl",
        groundTruth: "IOPlatformExpertDevice (firmware-level) vs sysctl (kernel-level) vs NVRAM (persistent storage)",
        adversaryCost: "Must patch IOKit registry AND sysctl values AND NVRAM — three independent subsystems",
        positiveDetection: "Shows hardware UUID, model, serial from each source with any disagreements",
        falsePositiveRate: "Near zero — hardware identity is set at manufacture and does not change"
    )

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        // Source 1: IOKit IOPlatformExpertDevice
        let iokitModel = readIOKitProperty("model")
        let iokitUUID = readIOKitProperty("IOPlatformUUID")
        let iokitSerial = readIOKitProperty("IOPlatformSerialNumber")

        // Source 2: sysctl hw.model
        // NOTE: kern.uuid is the KERNEL boot UUID (changes every boot), NOT the hardware UUID.
        // Do NOT compare it with IOPlatformUUID — they are fundamentally different values.
        let sysctlModel = readSysctl("hw.model")

        // Comparison 1: Model — IOKit vs sysctl
        if let iokit = iokitModel, let sysctl = sysctlModel {
            let match = iokit == sysctl
            if !match { hasContradiction = true }
            comparisons.append(SourceComparison(
                label: "hardware model",
                sourceA: SourceValue("IOKit IOPlatformExpertDevice", iokit),
                sourceB: SourceValue("sysctl hw.model", sysctl),
                matches: match))
        }

        // Comparison 2: Hardware UUID consistency — read IOKit twice to detect tampering.
        // If someone hooks IORegistryEntryCreateCFProperty, consecutive reads may differ.
        if let uuid1 = iokitUUID {
            let uuid2 = readIOKitProperty("IOPlatformUUID")
            let match = uuid1 == uuid2
            if !match { hasContradiction = true }
            let isValidFormat = uuid1.count == 36
                && uuid1.filter({ $0 == "-" }).count == 4
                && uuid1.allSatisfy({ $0.isHexDigit || $0 == "-" })
            if !isValidFormat { hasContradiction = true }
            comparisons.append(SourceComparison(
                label: "hardware UUID stability + format",
                sourceA: SourceValue("IOKit IOPlatformUUID (read 1)", uuid1),
                sourceB: SourceValue("IOKit IOPlatformUUID (read 2)", uuid2 ?? "nil"),
                matches: match && isValidFormat))
        }

        // Comparison 3: Serial number exists and is reasonable
        if let serial = iokitSerial {
            let reasonable = serial.count >= 8 && serial.count <= 14
                && serial.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) }
            comparisons.append(SourceComparison(
                label: "serial number format",
                sourceA: SourceValue("IOKit IOPlatformSerialNumber", serial),
                sourceB: SourceValue("expected format", "8-14 alphanumeric chars"),
                matches: reasonable))
            if !reasonable { hasContradiction = true }
        }

        // Source 3: NVRAM — CSR active config
        let nvramCSR = readNVRAMProperty("csr-active-config")
        let sysctlCSR = readCSRActiveConfig()
        if let nvram = nvramCSR, let kernel = sysctlCSR {
            let match = nvram == kernel
            if !match { hasContradiction = true }
            comparisons.append(SourceComparison(
                label: "CSR config: NVRAM vs kernel",
                sourceA: SourceValue("NVRAM csr-active-config", nvram),
                sourceB: SourceValue("csr_get_active_config()", kernel),
                matches: match))
        }

        // Source 3b: NVRAM boot-args
        let bootArgs = readNVRAMProperty("boot-args")
        if let args = bootArgs, !args.isEmpty {
            // Any boot-args on a production system is suspicious
            let suspicious = args.contains("amfi_get_out_of_my_way")
                || args.contains("cs_enforcement_disable")
                || args.contains("-v")  // verbose boot (common for research but notable)
            comparisons.append(SourceComparison(
                label: "NVRAM boot-args",
                sourceA: SourceValue("NVRAM boot-args", args),
                sourceB: SourceValue("expected", suspicious ? "suspicious flags detected" : "non-suspicious"),
                matches: !suspicious || !args.contains("amfi_get_out_of_my_way")))
        }

        // Check for SEP (Secure Enclave) presence
        let hasSEP = checkSEPPresence()
        comparisons.append(SourceComparison(
            label: "Secure Enclave presence",
            sourceA: SourceValue("IOKit AppleSEPManager", hasSEP ? "present" : "absent"),
            sourceB: SourceValue("expected (Apple Silicon)", "present"),
            matches: hasSEP))
        if !hasSEP { hasContradiction = true }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        let verdict: ProbeVerdict
        let message: String

        if comparisons.isEmpty {
            verdict = .degraded
            message = "Could not read hardware identity sources"
        } else if hasContradiction {
            let issues = comparisons.filter { !$0.matches }.count
            verdict = .contradiction
            message = "CONTRADICTION: \(issues) hardware identity mismatch(es)"
            logger.critical("HARDWARE IDENTITY CONTRADICTION: \(issues) mismatches")
        } else {
            verdict = .consistent
            message = "All \(comparisons.count) hardware identity sources agree"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    // MARK: - IOKit

    private func readIOKitProperty(_ key: String) -> String? {
        let service = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("IOPlatformExpertDevice"))
        guard service != MACH_PORT_NULL else { return nil }
        defer { IOObjectRelease(service) }
        guard let prop = IORegistryEntryCreateCFProperty(
            service, key as CFString, kCFAllocatorDefault, 0
        ) else { return nil }
        let value = prop.takeRetainedValue()
        if let str = value as? String { return str }
        if let data = value as? Data { return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .controlCharacters) }
        return nil
    }

    private func readNVRAMProperty(_ key: String) -> String? {
        let service = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("IOPlatformExpertDevice"))
        guard service != MACH_PORT_NULL else { return nil }
        defer { IOObjectRelease(service) }
        // NVRAM variables are accessible via the options node
        var iterator: io_iterator_t = 0
        guard IORegistryEntryCreateIterator(service, kIOServicePlane, IOOptionBits(kIORegistryIterateRecursively), &iterator) == KERN_SUCCESS else { return nil }
        defer { IOObjectRelease(iterator) }

        // Try reading NVRAM directly from the root registry
        let nvram = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/options")
        guard nvram != MACH_PORT_NULL else { return nil }
        defer { IOObjectRelease(nvram) }
        guard let prop = IORegistryEntryCreateCFProperty(
            nvram, key as CFString, kCFAllocatorDefault, 0
        ) else { return nil }
        let value = prop.takeRetainedValue()
        if let str = value as? String { return str }
        if let data = value as? Data {
            // csr-active-config is raw bytes — format as hex
            return data.map { String(format: "%02x", $0) }.joined()
        }
        return nil
    }

    private func readCSRActiveConfig() -> String? {
        var config: UInt32 = 0
        let result = iris_csr_get_active_config(&config)
        guard result == 0 else { return nil }
        return String(format: "%08x", config)
    }

    private func checkSEPPresence() -> Bool {
        let service = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("AppleSEPManager"))
        guard service != MACH_PORT_NULL else { return false }
        IOObjectRelease(service)
        return true
    }

    private func readSysctl(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return nil }
        return String(cString: buf)
    }
}
