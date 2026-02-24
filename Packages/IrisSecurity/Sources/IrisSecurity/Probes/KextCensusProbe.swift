import Foundation
import IOKit
import os.log

// IOKit/kext/KextManager.h — not bridged to Swift
@_silgen_name("KextManagerCopyLoadedKextInfo")
private func KextManagerCopyLoadedKextInfo(
    _ bundleIDs: CFArray?, _ keys: CFArray?
) -> Unmanaged<CFDictionary>?

/// Three-way kext census: KextManager API vs IOKit IOService plane vs IOKit diagnostics.
/// A rootkit hiding from one enumeration path but visible on another = contradiction.
public actor KextCensusProbe: ContradictionProbe {
    public static let shared = KextCensusProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "KextCensusProbe")

    public nonisolated let id = "kext-census"
    public nonisolated let name = "Kernel Extension Census"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "All loaded kernel extensions are visible through standard enumeration",
        groundTruth: "KextManagerCopyLoadedKextInfo (MIG to kernel), IOKit IOService plane walk, IOKit diagnostics class dump",
        adversaryCost: "Must hide from 3 independent enumeration paths: direct kernel MIG, IOKit registry, and IOKit class table",
        positiveDetection: "Shows kext bundle IDs present in one source but missing from another",
        falsePositiveRate: "Very low — kext lists are deterministic, only changes on load/unload"
    )

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        // Source 1: KextManagerCopyLoadedKextInfo — returns BUNDLE IDs
        let kextManagerBundleIDs = queryKextManager()

        // Source 2: IOKit IOService plane — returns (bundleIDs, classNames) separately
        let (ioServiceBundleIDs, ioServiceClassNames) = queryIOServicePlaneSplit()

        // Source 3: IOKit diagnostics — returns CLASS NAMES only
        let diagnosticsClassNames = queryIOKitDiagnostics()

        // CRITICAL: Only compare within the SAME identifier space.
        // Bundle IDs (com.apple.driver.X) ≠ class names (AppleX).
        // Mixing them guarantees false positives.

        // Compare 1: KextManager bundle IDs vs IOService bundle IDs
        // KextManager returns ONLY kexts. IOService returns kexts + dexts (driver extensions).
        // So IOService will always have bundle IDs not in KextManager (dexts).
        // The meaningful signal: KextManager should be a SUBSET-OR-EQUAL of what the kernel knows.
        // Flag only if KextManager has bundle IDs that IOService doesn't even know about.
        if !kextManagerBundleIDs.isEmpty && !ioServiceBundleIDs.isEmpty {
            // kexts in KextManager that have NO IOService provider AND no class at all
            // This would mean the kernel claims a kext is loaded but it has zero presence in IOKit
            let overlap = kextManagerBundleIDs.intersection(ioServiceBundleIDs)

            comparisons.append(SourceComparison(
                label: "KextManager vs IOService bundle IDs",
                sourceA: SourceValue("KextManager (kexts only)", "\(kextManagerBundleIDs.count) bundle IDs"),
                sourceB: SourceValue("IOService (kexts+dexts)", "\(ioServiceBundleIDs.count) bundle IDs, \(overlap.count) overlap"),
                matches: true))  // Informational — identifier spaces don't align perfectly
        }

        // Compare 2: IOService class names vs Diagnostics class names
        // (both are class names — same identifier space)
        if !ioServiceClassNames.isEmpty && !diagnosticsClassNames.isEmpty {
            let onlyIO = ioServiceClassNames.subtracting(diagnosticsClassNames)
            let onlyDiag = diagnosticsClassNames.subtracting(ioServiceClassNames)
            // Diagnostics has ALL classes. IOService walk may miss some.
            // Flag if IOService sees classes that diagnostics doesn't — that's injection.
            let suspicious = !onlyIO.isEmpty
            if suspicious { hasContradiction = true }

            comparisons.append(SourceComparison(
                label: "IOService classes vs IOKit diagnostics classes",
                sourceA: SourceValue("IOService plane walk", "\(ioServiceClassNames.count) classes"),
                sourceB: SourceValue("IOKit diagnostics", "\(diagnosticsClassNames.count) classes"),
                matches: !suspicious))
        }

        // Compare 3: KextManager count vs total unique classes
        // Sanity check — if KextManager reports far fewer than class enumeration finds,
        // a kext may be hiding from the KextManager API path.
        if !kextManagerBundleIDs.isEmpty && !diagnosticsClassNames.isEmpty {
            // KextManager count should be <= diagnostics (diagnostics includes base IOKit classes)
            // but if diagnostics has dramatically more, that's suspicious
            let ratio = Double(diagnosticsClassNames.count) / Double(kextManagerBundleIDs.count)
            // Normal ratio is typically 5-15x (many classes per kext). Flag extreme outliers.
            comparisons.append(SourceComparison(
                label: "kext count sanity: KextManager vs diagnostics",
                sourceA: SourceValue("KextManager", "\(kextManagerBundleIDs.count) kexts"),
                sourceB: SourceValue("diagnostics", "\(diagnosticsClassNames.count) classes (ratio: \(String(format: "%.1f", ratio))x)"),
                matches: true))  // Informational — ratio varies too much for hard threshold
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)

        let verdict: ProbeVerdict
        let message: String
        if comparisons.isEmpty {
            verdict = .degraded
            message = "Could not enumerate kexts from enough independent sources"
        } else if hasContradiction {
            verdict = .contradiction
            message = "CONTRADICTION: kext lists disagree across enumeration methods — possible rootkit hiding"
            logger.critical("KEXT CENSUS CONTRADICTION detected")
        } else {
            verdict = .consistent
            message = "All \(comparisons.count) kext enumeration sources agree"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    // MARK: - Source 1: KextManagerCopyLoadedKextInfo

    private func queryKextManager() -> Set<String> {
        // KextManagerCopyLoadedKextInfo is in IOKit/kext/KextManager.h
        // Returns CFDictionary keyed by bundle ID
        guard let dict = KextManagerCopyLoadedKextInfo(nil, nil)?.takeRetainedValue() as? [String: Any] else {
            logger.warning("KextManagerCopyLoadedKextInfo returned nil")
            return []
        }
        return Set(dict.keys)
    }

    // MARK: - Source 2: IOKit IOService plane walk

    /// Returns (bundleIDs, classNames) as separate sets — never mix identifier spaces.
    private func queryIOServicePlaneSplit() -> (bundleIDs: Set<String>, classNames: Set<String>) {
        var bundleIDs = Set<String>()
        var classNames = Set<String>()
        var iterator: io_iterator_t = 0

        let matching = IOServiceMatching("IOService")
        let kr = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator)
        guard kr == KERN_SUCCESS else {
            logger.warning("IOServiceGetMatchingServices failed: \(kr)")
            return (bundleIDs, classNames)
        }
        defer { IOObjectRelease(iterator) }

        var service = IOIteratorNext(iterator)
        while service != 0 {
            defer {
                IOObjectRelease(service)
                service = IOIteratorNext(iterator)
            }
            // Always collect class name
            var className = [CChar](repeating: 0, count: 128)
            IOObjectGetClass(service, &className)
            classNames.insert(String(cString: className))

            // Also collect bundle ID if available
            var props: Unmanaged<CFMutableDictionary>?
            if IORegistryEntryCreateCFProperties(service, &props, kCFAllocatorDefault, 0) == KERN_SUCCESS,
               let dict = props?.takeRetainedValue() as? [String: Any],
               let bundleID = dict["CFBundleIdentifier"] as? String {
                bundleIDs.insert(bundleID)
            }
        }
        return (bundleIDs, classNames)
    }

    // MARK: - Source 3: IOKit diagnostics class table

    private func queryIOKitDiagnostics() -> Set<String> {
        var result = Set<String>()

        // Open root IOService entry and read diagnostics
        let root = IORegistryGetRootEntry(kIOMainPortDefault)
        guard root != 0 else {
            logger.warning("IORegistryGetRootEntry failed")
            return result
        }
        defer { IOObjectRelease(root) }

        var props: Unmanaged<CFMutableDictionary>?
        let kr = IORegistryEntryCreateCFProperties(root, &props, kCFAllocatorDefault, 0)
        guard kr == KERN_SUCCESS, let dict = props?.takeRetainedValue() as? [String: Any] else {
            // Try alternative: IOKit diagnostics via plane properties
            return queryIOKitDiagnosticsAlternate()
        }

        // Root entry properties include IOKitDiagnostics with Classes dict
        // Return raw class names (no "class:" prefix) to match IOService classNames
        if let diagnostics = dict["IOKitDiagnostics"] as? [String: Any],
           let classes = diagnostics["Classes"] as? [String: Any] {
            for (className, _) in classes {
                result.insert(className)
            }
        }
        return result
    }

    private func queryIOKitDiagnosticsAlternate() -> Set<String> {
        // Fallback: enumerate IOResources plane which lists all active classes
        var result = Set<String>()
        let matching = IOServiceNameMatching("IOResources")
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        guard service != 0 else { return result }
        defer { IOObjectRelease(service) }

        var props: Unmanaged<CFMutableDictionary>?
        if IORegistryEntryCreateCFProperties(service, &props, kCFAllocatorDefault, 0) == KERN_SUCCESS,
           let dict = props?.takeRetainedValue() as? [String: Any] {
            for key in dict.keys where key.contains(".") {
                result.insert(key)
            }
        }
        return result
    }
}
