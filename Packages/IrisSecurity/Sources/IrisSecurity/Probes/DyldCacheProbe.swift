import Foundation
import os.log

// Private dyld APIs — from <mach-o/dyld_priv.h>
@_silgen_name("_dyld_get_shared_cache_uuid")
private func _dyld_get_shared_cache_uuid(_ uuid: UnsafeMutablePointer<uuid_t>) -> Bool

@_silgen_name("_dyld_get_shared_cache_range")
private func _dyld_get_shared_cache_range(_ length: UnsafeMutablePointer<Int>) -> UnsafeRawPointer?

/// Three-way contradiction: disk cache header UUID vs runtime API vs mapped memory.
/// If any two disagree, the shared cache has been tampered with or the API is hooked.
public actor DyldCacheProbe: ContradictionProbe {
    public static let shared = DyldCacheProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "DyldCacheProbe")

    public nonisolated let id = "dyld-cache"
    public nonisolated let name = "Dyld Shared Cache"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "The dyld shared cache in memory is the one Apple shipped",
        groundTruth: "Read UUID from disk cache header (offset 0x58), query _dyld_get_shared_cache_uuid(), read UUID from mapped memory directly",
        adversaryCost: "Must patch 3 independent sources simultaneously: disk file, dyld API return value, and mapped memory region",
        positiveDetection: "Shows which source disagrees and exact UUID values from each",
        falsePositiveRate: "Near zero — UUIDs are deterministic, only changes on OS update"
    )

    private let uuidOffset = 0x58

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        // Source 1: Runtime UUID from dyld API
        let runtimeUUID = getRuntimeCacheUUID()

        // Source 2: Disk UUID from cache file header
        let cachePaths = findSharedCachePaths()
        var diskUUID: String?
        for path in cachePaths {
            if let uuid = readDiskCacheUUID(path: path) {
                diskUUID = uuid
                break
            }
        }

        // Source 3: UUID from mapped memory (bypass API hooking)
        let memoryUUID = getMappedMemoryUUID()

        // Build comparisons
        if let runtime = runtimeUUID, let disk = diskUUID {
            let match = runtime == disk
            if !match { hasContradiction = true }
            comparisons.append(SourceComparison(
                label: "disk header UUID vs runtime API UUID",
                sourceA: SourceValue("disk header (0x58)", disk),
                sourceB: SourceValue("_dyld_get_shared_cache_uuid()", runtime),
                matches: match))
        }

        if let runtime = runtimeUUID, let memory = memoryUUID {
            let match = runtime == memory
            if !match { hasContradiction = true }
            comparisons.append(SourceComparison(
                label: "runtime API UUID vs mapped memory UUID",
                sourceA: SourceValue("_dyld_get_shared_cache_uuid()", runtime),
                sourceB: SourceValue("mapped memory (0x58)", memory),
                matches: match))
        }

        if let disk = diskUUID, let memory = memoryUUID {
            let match = disk == memory
            if !match { hasContradiction = true }
            comparisons.append(SourceComparison(
                label: "disk header UUID vs mapped memory UUID",
                sourceA: SourceValue("disk header (0x58)", disk),
                sourceB: SourceValue("mapped memory (0x58)", memory),
                matches: match))
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)

        // Determine verdict
        let verdict: ProbeVerdict
        let message: String
        if comparisons.isEmpty {
            verdict = .degraded
            message = "Could not read enough sources for comparison"
        } else if hasContradiction {
            verdict = .contradiction
            let mismatches = comparisons.filter { !$0.matches }
            message = "CONTRADICTION: \(mismatches.count) UUID mismatch(es) — shared cache tampering or API hooking"
            logger.critical("SHARED CACHE CONTRADICTION: \(mismatches.count) mismatches")
        } else {
            verdict = .consistent
            message = "All \(comparisons.count) UUID sources agree — cache is consistent"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    // MARK: - Sources

    private func getRuntimeCacheUUID() -> String? {
        var uuid = uuid_t(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
        guard _dyld_get_shared_cache_uuid(&uuid) else { return nil }
        return uuidToString(uuid)
    }

    private func getMappedMemoryUUID() -> String? {
        var length: Int = 0
        guard let ptr = _dyld_get_shared_cache_range(&length), length > 0 else { return nil }
        let magic = String(cString: ptr.assumingMemoryBound(to: CChar.self))
        guard magic.hasPrefix("dyld_v1") else { return nil }
        let uuidPtr = (ptr + uuidOffset).assumingMemoryBound(to: uuid_t.self)
        return uuidToString(uuidPtr.pointee)
    }

    private func findSharedCachePaths() -> [String] {
        var paths: [String] = []
        let cryptex = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
        if FileManager.default.fileExists(atPath: cryptex) { paths.append(cryptex) }
        let primary = "/System/Library/dyld/dyld_shared_cache_arm64e"
        if FileManager.default.fileExists(atPath: primary) && primary != cryptex { paths.append(primary) }
        return paths
    }

    private func readDiskCacheUUID(path: String) -> String? {
        guard let fh = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? fh.close() }
        let needed = uuidOffset + 16
        guard let data = try? fh.read(upToCount: needed), data.count == needed else { return nil }
        let magic = data.prefix(15).map { $0 == 0 ? 0x20 : $0 }
        guard String(bytes: magic, encoding: .ascii)?.hasPrefix("dyld_v1") == true else { return nil }
        return data.subdata(in: uuidOffset..<(uuidOffset + 16)).withUnsafeBytes { ptr in
            uuidToString(ptr.load(as: uuid_t.self))
        }
    }

    private func uuidToString(_ uuid: uuid_t) -> String {
        let u = uuid
        return String(format: "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                       u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7,
                       u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15)
    }
}
