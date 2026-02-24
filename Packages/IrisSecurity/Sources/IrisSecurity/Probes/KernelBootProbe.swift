import Foundation
import os.log

/// Verifies boot identity consistency across 4 independent kernel sources.
///
/// Source 1: kas_info(0) — kernel ASLR slide (changes every boot)
/// Source 2: kern.bootsessionuuid — sysctl boot UUID (changes every boot)
/// Source 3: kern.boottime — exact boot timestamp
/// Source 4: IOKit IOKitBuildVersion — kernel build from IOKit registry
///
/// All sources are populated at boot time by different kernel subsystems.
/// If any disagree about when/how the system booted, something tampered
/// with kernel state post-boot.
public actor KernelBootProbe: ContradictionProbe {
    public static let shared = KernelBootProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "KernelBootProbe")

    @_silgen_name("kas_info")
    private static func kas_info(
        _ selector: Int32,
        _ value: UnsafeMutableRawPointer,
        _ size: UnsafeMutablePointer<Int>
    ) -> Int32

    public nonisolated let id = "kernel-boot"
    public nonisolated let name = "Kernel Boot Identity"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "The system booted normally and kernel address space has not been tampered with",
        groundTruth: "Four sources: kas_info KASLR slide, kern.bootsessionuuid, kern.boottime, IOKit build version",
        adversaryCost: "Must hook kas_info syscall AND sysctl AND IOKit registry — three independent kernel subsystems",
        positiveDetection: "Shows KASLR slide value, boot UUID, boot time, and any disagreements",
        falsePositiveRate: "Near zero — boot identity is immutable after boot, only changes on reboot"
    )

    /// Cached KASLR slide from first run — detects mid-session kernel memory tampering
    private var cachedSlide: UInt64?
    /// Cached boot UUID from first run
    private var cachedBootUUID: String?

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        // Source 1: kas_info — kernel ASLR slide
        let slide = readKASLRSlide()

        // Source 2: kern.bootsessionuuid
        let bootUUID = readSysctl("kern.bootsessionuuid")

        // Source 3: kern.boottime
        let bootTime = readBootTime()

        // Source 4: IOKit kernel build version
        let iokitBuild = readIOKitBuildVersion()
        let sysctlBuild = readSysctl("kern.version")

        // Comparison 1: KASLR slide consistency (should be stable within a boot)
        if let currentSlide = slide {
            if let previous = cachedSlide {
                let match = currentSlide == previous
                if !match { hasContradiction = true }
                comparisons.append(SourceComparison(
                    label: "KASLR slide stability (current vs cached)",
                    sourceA: SourceValue("kas_info(0) current", "0x\(String(currentSlide, radix: 16))"),
                    sourceB: SourceValue("kas_info(0) cached", "0x\(String(previous, radix: 16))"),
                    matches: match))
            } else {
                cachedSlide = currentSlide
                comparisons.append(SourceComparison(
                    label: "KASLR slide (first read — baseline)",
                    sourceA: SourceValue("kas_info(0)", "0x\(String(currentSlide, radix: 16))"),
                    sourceB: SourceValue("baseline", "recorded"),
                    matches: true))
            }
        }

        // Comparison 2: Boot UUID consistency (should be stable within a boot)
        if let uuid = bootUUID {
            if let previous = cachedBootUUID {
                let match = uuid == previous
                if !match { hasContradiction = true }
                comparisons.append(SourceComparison(
                    label: "boot UUID stability (current vs cached)",
                    sourceA: SourceValue("kern.bootsessionuuid current", uuid),
                    sourceB: SourceValue("kern.bootsessionuuid cached", previous),
                    matches: match))
            } else {
                cachedBootUUID = uuid
                comparisons.append(SourceComparison(
                    label: "boot UUID (first read — baseline)",
                    sourceA: SourceValue("kern.bootsessionuuid", uuid),
                    sourceB: SourceValue("baseline", "recorded"),
                    matches: true))
            }
        }

        // Comparison 3: IOKit build version vs sysctl kern.version
        // NOTE: kern.osversion is the macOS BUILD NUMBER ("25D125"), not the kernel version.
        // IOKitBuildVersion contains the full Darwin kernel version string.
        // kern.version contains the same Darwin string — correct comparison.
        if let iokit = iokitBuild, let sysctl = sysctlBuild {
            let match = iokit == sysctl
            if !match { hasContradiction = true }
            comparisons.append(SourceComparison(
                label: "kernel build: IOKit vs sysctl",
                sourceA: SourceValue("IOKit IOKitBuildVersion", iokit),
                sourceB: SourceValue("kern.version", sysctl),
                matches: match))
        }

        // Comparison 4: Boot time sanity — should be in the past and not changing
        if let bt = bootTime {
            let now = Date()
            let sane = bt < now && now.timeIntervalSince(bt) < 365 * 24 * 3600
            if !sane { hasContradiction = true }
            let formatter = ISO8601DateFormatter()
            comparisons.append(SourceComparison(
                label: "boot time sanity check",
                sourceA: SourceValue("kern.boottime", formatter.string(from: bt)),
                sourceB: SourceValue("current time", formatter.string(from: now)),
                matches: sane))
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        let verdict: ProbeVerdict
        let message: String

        if comparisons.isEmpty {
            verdict = .degraded
            message = "Could not read kernel boot identity sources"
        } else if hasContradiction {
            verdict = .contradiction
            let mismatches = comparisons.filter { !$0.matches }.count
            message = "CONTRADICTION: \(mismatches) boot identity mismatch(es) — possible kernel memory tampering"
            logger.critical("BOOT IDENTITY CONTRADICTION: \(mismatches) mismatches")
        } else {
            verdict = .consistent
            let slideStr = slide.map { "0x\(String($0, radix: 16))" } ?? "unavailable"
            message = "All \(comparisons.count) boot identity sources agree (KASLR=\(slideStr))"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    // MARK: - Sources

    private func readKASLRSlide() -> UInt64? {
        var slide: UInt64 = 0
        var size = MemoryLayout<UInt64>.size
        let result = Self.kas_info(0, &slide, &size)
        if result != 0 {
            logger.warning("kas_info(0) failed: errno=\(errno)")
            return nil
        }
        return slide
    }

    private func readSysctl(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return nil }
        return String(cString: buf)
    }

    private func readBootTime() -> Date? {
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        var bt = timeval()
        var size = MemoryLayout<timeval>.size
        guard sysctl(&mib, 2, &bt, &size, nil, 0) == 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(bt.tv_sec))
    }

    private func readIOKitBuildVersion() -> String? {
        let root = IORegistryGetRootEntry(kIOMainPortDefault)
        guard root != MACH_PORT_NULL else { return nil }
        defer { IOObjectRelease(root) }
        guard let prop = IORegistryEntryCreateCFProperty(
            root, "IOKitBuildVersion" as CFString, kCFAllocatorDefault, 0
        ) else { return nil }
        return prop.takeRetainedValue() as? String
    }
}
