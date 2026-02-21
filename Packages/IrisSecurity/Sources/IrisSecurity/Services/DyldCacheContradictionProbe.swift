import Foundation
import os.log

// Private dyld APIs — from <mach-o/dyld_priv.h>
// These are available in libdyld.dylib on all macOS versions
@_silgen_name("_dyld_get_shared_cache_uuid")
private func _dyld_get_shared_cache_uuid(_ uuid: UnsafeMutablePointer<uuid_t>) -> Bool

@_silgen_name("_dyld_get_shared_cache_range")
private func _dyld_get_shared_cache_range(_ length: UnsafeMutablePointer<Int>) -> UnsafeRawPointer?

/// Compares the dyld shared cache UUID on disk against what the runtime reports.
///
/// Lie detected: "The shared cache in memory is the one Apple shipped"
/// Ground truth: Read the cache file header directly from disk, extract UUID.
///               Query _dyld_get_shared_cache_uuid() for what the runtime thinks.
///               If they differ, someone replaced the cache or is intercepting the API.
///
/// Also checks: The cache file's UUID matches what's mapped into OUR process.
/// A sophisticated attacker might swap the cache after boot but before our check.
///
/// Adversary cost: Would need to either:
/// (a) Replace the shared cache AND hook _dyld_get_shared_cache_uuid — expensive
/// (b) Patch our process's memory to fake the runtime UUID — requires knowing we check
/// (c) Modify the cache in-place while maintaining the UUID — nearly impossible (sealed volume)
public actor DyldCacheContradictionProbe {
    public static let shared = DyldCacheContradictionProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "DyldCacheContradiction")

    /// dyld_cache_header magic values
    private let arm64eMagic = "dyld_v1  arm64e" // 16 bytes padded with spaces
    private let arm64Magic  = "dyld_v1   arm64"

    /// UUID is at offset 0x58 (88) in dyld_cache_header
    /// Verified from dyld source and actual disk read
    private let uuidOffset = 0x58

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // Source 1: Runtime UUID from dyld
        guard let runtimeUUID = getRuntimeCacheUUID() else {
            logger.warning("Could not get runtime shared cache UUID")
            return []
        }

        // Source 2: Disk UUID from the actual cache file
        let cachePaths = findSharedCachePaths()
        guard !cachePaths.isEmpty else {
            logger.warning("No shared cache files found on disk")
            return []
        }

        for cachePath in cachePaths {
            guard let diskUUID = readDiskCacheUUID(path: cachePath) else { continue }

            if diskUUID != runtimeUUID {
                anomalies.append(.filesystem(
                    name: "dyld_shared_cache",
                    path: cachePath,
                    technique: "Shared Cache Tampering",
                    description: "CRITICAL: dyld shared cache UUID on disk does NOT match runtime UUID. The loaded shared cache has been replaced or the UUID API is hooked.",
                    severity: .critical, mitreID: "T1574.006",
                    scannerId: "dyld_cache_contradiction",
                    enumMethod: "disk cache header UUID vs _dyld_get_shared_cache_uuid()",
                    evidence: [
                        "cache_path: \(cachePath)",
                        "disk_uuid: \(diskUUID)",
                        "runtime_uuid: \(runtimeUUID)",
                    ]))
                logger.critical("SHARED CACHE MISMATCH: disk=\(diskUUID) runtime=\(runtimeUUID)")
            }
        }

        // Source 3: Cross-check the mapped cache range
        if let (mappedAddr, mappedSize) = getMappedCacheRange() {
            // Read UUID directly from mapped memory (bypass any API hooking)
            let memUUID = readUUIDFromMappedMemory(address: mappedAddr)
            if let memUUID, memUUID != runtimeUUID {
                anomalies.append(.filesystem(
                    name: "dyld_shared_cache",
                    path: "memory://\(String(format: "0x%llx", mappedAddr))",
                    technique: "Shared Cache API Hooking",
                    description: "CRITICAL: _dyld_get_shared_cache_uuid() returns different UUID than what's actually mapped in memory. The API is being hooked.",
                    severity: .critical, mitreID: "T1574.006",
                    scannerId: "dyld_cache_contradiction",
                    enumMethod: "mapped memory UUID vs _dyld_get_shared_cache_uuid()",
                    evidence: [
                        "mapped_addr: \(String(format: "0x%llx", mappedAddr))",
                        "mapped_size: \(mappedSize)",
                        "memory_uuid: \(memUUID)",
                        "api_uuid: \(runtimeUUID)",
                    ]))
            }
        }

        logger.info("DyldCache probe: checked \(cachePaths.count) cache files, \(anomalies.count) contradictions")
        return anomalies
    }

    // MARK: - Runtime UUID

    private func getRuntimeCacheUUID() -> String? {
        var uuid = uuid_t(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
        guard _dyld_get_shared_cache_uuid(&uuid) else { return nil }
        return uuidToString(uuid)
    }

    // MARK: - Mapped Cache Range

    private func getMappedCacheRange() -> (UInt64, UInt64)? {
        var length: Int = 0
        guard let ptr = _dyld_get_shared_cache_range(&length), length > 0 else { return nil }
        return (UInt64(Int(bitPattern: ptr)), UInt64(length))
    }

    private func readUUIDFromMappedMemory(address: UInt64) -> String? {
        let ptr = UnsafeRawPointer(bitPattern: UInt(address))
        guard let ptr else { return nil }
        // Verify magic first
        let magic = String(cString: ptr.assumingMemoryBound(to: CChar.self))
        guard magic.hasPrefix("dyld_v1") else { return nil }
        // UUID at offset 16
        let uuidPtr = (ptr + uuidOffset).assumingMemoryBound(to: uuid_t.self)
        return uuidToString(uuidPtr.pointee)
    }

    // MARK: - Disk Cache Reading

    private func findSharedCachePaths() -> [String] {
        var paths: [String] = []
        // Cryptex location (Ventura+, where the cache actually lives)
        let cryptex = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
        if FileManager.default.fileExists(atPath: cryptex) {
            paths.append(cryptex)
        }
        // Primary location (firmlink to cryptex)
        let primary = "/System/Library/dyld/dyld_shared_cache_arm64e"
        if FileManager.default.fileExists(atPath: primary) && primary != cryptex {
            paths.append(primary)
        }
        // Also check preboot boot containers
        let prebootBase = "/System/Volumes/Preboot"
        if let contents = try? FileManager.default.contentsOfDirectory(atPath: prebootBase) {
            for dir in contents {
                let cachePath = "\(prebootBase)/\(dir)/boot"
                if let bootDirs = try? FileManager.default.contentsOfDirectory(atPath: cachePath) {
                    for bootDir in bootDirs {
                        let full = "\(cachePath)/\(bootDir)/System/Library/dyld/dyld_shared_cache_arm64e"
                        if FileManager.default.fileExists(atPath: full) {
                            paths.append(full)
                        }
                    }
                }
            }
        }
        return paths
    }

    private func readDiskCacheUUID(path: String) -> String? {
        guard let fh = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? fh.close() }
        // Read enough for magic(16) + ... + uuid at 0x58(16) = need 0x68 = 104 bytes
        let needed = uuidOffset + 16
        guard let data = try? fh.read(upToCount: needed), data.count == needed else { return nil }
        // Verify magic
        let magic = data.prefix(15).map { $0 == 0 ? 0x20 : $0 }
        guard String(bytes: magic, encoding: .ascii)?.hasPrefix("dyld_v1") == true else { return nil }
        // Extract UUID at offset 0x58
        let uuidBytes = data.subdata(in: uuidOffset..<(uuidOffset + 16))
        return uuidBytes.withUnsafeBytes { ptr -> String in
            let uuid = ptr.load(as: uuid_t.self)
            return uuidToString(uuid)
        }
    }

    // MARK: - Helpers

    private func uuidToString(_ uuid: uuid_t) -> String {
        let u = uuid
        return String(format: "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                       u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7,
                       u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15)
    }
}
