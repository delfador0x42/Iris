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

        // Source 1: KextManagerCopyLoadedKextInfo — MIG kext_request to kernel
        let kextManagerSet = queryKextManager()

        // Source 2: IOKit IOService plane — walk registry for kext class instances
        let ioServiceSet = queryIOServicePlane()

        // Source 3: IOKit diagnostics — class table with instance counts
        let diagnosticsSet = queryIOKitDiagnostics()

        // Compare: KextManager vs IOService
        if !kextManagerSet.isEmpty && !ioServiceSet.isEmpty {
            let onlyKM = kextManagerSet.subtracting(ioServiceSet)
            let onlyIO = ioServiceSet.subtracting(kextManagerSet)
            let match = onlyKM.isEmpty && onlyIO.isEmpty
            if !match { hasContradiction = true }

            var detail = "KextManager: \(kextManagerSet.count), IOService: \(ioServiceSet.count)"
            if !onlyKM.isEmpty { detail += " | only-KM: \(onlyKM.sorted().prefix(5).joined(separator: ","))" }
            if !onlyIO.isEmpty { detail += " | only-IO: \(onlyIO.sorted().prefix(5).joined(separator: ","))" }

            comparisons.append(SourceComparison(
                label: "KextManager vs IOService plane",
                sourceA: SourceValue("KextManagerCopyLoadedKextInfo", "\(kextManagerSet.count) kexts"),
                sourceB: SourceValue("IOService plane walk", "\(ioServiceSet.count) kext classes"),
                matches: match))
        }

        // Compare: KextManager vs Diagnostics
        if !kextManagerSet.isEmpty && !diagnosticsSet.isEmpty {
            let onlyKM = kextManagerSet.subtracting(diagnosticsSet)
            let onlyDiag = diagnosticsSet.subtracting(kextManagerSet)
            let match = onlyKM.isEmpty && onlyDiag.isEmpty
            if !match { hasContradiction = true }

            comparisons.append(SourceComparison(
                label: "KextManager vs IOKit diagnostics",
                sourceA: SourceValue("KextManagerCopyLoadedKextInfo", "\(kextManagerSet.count) kexts"),
                sourceB: SourceValue("IOKit diagnostics classes", "\(diagnosticsSet.count) classes"),
                matches: match))
        }

        // Compare: IOService vs Diagnostics
        if !ioServiceSet.isEmpty && !diagnosticsSet.isEmpty {
            let onlyIO = ioServiceSet.subtracting(diagnosticsSet)
            let onlyDiag = diagnosticsSet.subtracting(ioServiceSet)
            let match = onlyIO.isEmpty && onlyDiag.isEmpty
            if !match { hasContradiction = true }

            comparisons.append(SourceComparison(
                label: "IOService plane vs IOKit diagnostics",
                sourceA: SourceValue("IOService plane walk", "\(ioServiceSet.count) kext classes"),
                sourceB: SourceValue("IOKit diagnostics classes", "\(diagnosticsSet.count) classes"),
                matches: match))
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

    private func queryIOServicePlane() -> Set<String> {
        var result = Set<String>()
        var iterator: io_iterator_t = 0

        // Match all IOService entries
        let matching = IOServiceMatching("IOService")
        let kr = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator)
        guard kr == KERN_SUCCESS else {
            logger.warning("IOServiceGetMatchingServices failed: \(kr)")
            return result
        }
        defer { IOObjectRelease(iterator) }

        var service = IOIteratorNext(iterator)
        while service != 0 {
            defer {
                IOObjectRelease(service)
                service = IOIteratorNext(iterator)
            }
            // Get the class name — maps back to kext providing it
            var className = [CChar](repeating: 0, count: 128)
            IOObjectGetClass(service, &className)
            let name = String(cString: className)

            // Get the bundle ID if available from IOKit properties
            var props: Unmanaged<CFMutableDictionary>?
            if IORegistryEntryCreateCFProperties(service, &props, kCFAllocatorDefault, 0) == KERN_SUCCESS,
               let dict = props?.takeRetainedValue() as? [String: Any],
               let bundleID = dict["CFBundleIdentifier"] as? String {
                result.insert(bundleID)
            } else {
                // Use class name as identifier when no bundle ID
                result.insert("class:\(name)")
            }
        }
        return result
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
        if let diagnostics = dict["IOKitDiagnostics"] as? [String: Any],
           let classes = diagnostics["Classes"] as? [String: Any] {
            for (className, _) in classes {
                result.insert("class:\(className)")
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
                result.insert("class:\(key)")
            }
        }
        return result
    }
}
