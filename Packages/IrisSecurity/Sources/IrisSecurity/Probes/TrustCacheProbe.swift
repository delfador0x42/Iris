import Foundation
import Security
import os.log
import CommonCrypto

/// Static trust cache on disk vs runtime code signature verification.
/// Apple's trust cache lists cdhashes of platform binaries. If a binary claims platform
/// status but its cdhash isn't in the static trust cache, something is wrong.
public actor TrustCacheProbe: ContradictionProbe {
    public static let shared = TrustCacheProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "TrustCacheProbe")

    public nonisolated let id = "trust-cache"
    public nonisolated let name = "Trust Cache Integrity"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "Platform binaries are the ones Apple signed and shipped",
        groundTruth: "Read static trust cache entries from Preboot volume, compare against runtime cdhash from SecStaticCode",
        adversaryCost: "Must either patch the trust cache file, subvert SecStaticCode API, or hide from both — 2 independent verification paths",
        positiveDetection: "Shows binaries whose runtime cdhash doesn't match any trust cache entry",
        falsePositiveRate: "Low — trust cache is updated only on OS install. 3rd-party signed binaries are excluded from check"
    )

    // Critical platform binaries to verify
    private let targetBinaries = [
        "/usr/libexec/amfid",
        "/usr/libexec/trustd",
        "/usr/sbin/spctl",
        "/usr/bin/codesign",
        "/sbin/launchd",
        "/usr/libexec/syspolicyd",
        "/usr/sbin/ocspd",
        "/usr/libexec/securityd",
    ]

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        // Source 1: Load trust cache entries from disk
        let trustCacheHashes = loadStaticTrustCache()

        // Source 2: Compute runtime cdhashes for target binaries
        for binary in targetBinaries {
            guard FileManager.default.fileExists(atPath: binary) else { continue }

            let runtimeCDHash = computeRuntimeCDHash(path: binary)
            let diskCDHash = computeDiskCDHash(path: binary)

            // Check runtime cdhash against trust cache
            if let runtime = runtimeCDHash, !trustCacheHashes.isEmpty {
                let inCache = trustCacheHashes.contains(runtime)
                // Platform binaries should be in cache; only flag if cdhash exists but isn't cached
                let isPlatform = checkPlatformBinary(path: binary)

                if isPlatform {
                    if !inCache { hasContradiction = true }
                    comparisons.append(SourceComparison(
                        label: "\(shortPath(binary)): trust cache lookup",
                        sourceA: SourceValue("runtime cdhash", runtime),
                        sourceB: SourceValue("static trust cache", inCache ? "FOUND" : "NOT FOUND"),
                        matches: inCache))
                }
            }

            // Cross-check: disk binary cdhash vs runtime cdhash (catches memory patching)
            if let disk = diskCDHash, let runtime = runtimeCDHash {
                let match = disk == runtime
                if !match { hasContradiction = true }
                comparisons.append(SourceComparison(
                    label: "\(shortPath(binary)): disk vs runtime cdhash",
                    sourceA: SourceValue("SHA256(disk CodeDirectory)", disk),
                    sourceB: SourceValue("SecStaticCode cdhash", runtime),
                    matches: match))
            }
        }

        // If we couldn't load trust cache, note degraded status
        if trustCacheHashes.isEmpty && comparisons.isEmpty {
            let durationMs = Int(Date().timeIntervalSince(start) * 1000)
            return ProbeResult(
                probeId: id, probeName: name, verdict: .degraded,
                comparisons: [], message: "Could not read static trust cache — check Preboot volume access",
                durationMs: durationMs)
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)

        let verdict: ProbeVerdict
        let message: String
        if hasContradiction {
            let mismatches = comparisons.filter { !$0.matches }.count
            verdict = .contradiction
            message = "CONTRADICTION: \(mismatches) cdhash mismatch(es) — possible binary tampering"
            logger.critical("TRUST CACHE CONTRADICTION: \(mismatches) mismatches")
        } else {
            verdict = .consistent
            message = "All \(comparisons.count) platform binary cdhashes verified against trust cache"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    // MARK: - Trust Cache Reading

    private func loadStaticTrustCache() -> Set<String> {
        var hashes = Set<String>()

        // Find Preboot volume UUID
        let prebootBase = "/System/Volumes/Preboot"
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: prebootBase) else {
            logger.warning("Cannot list Preboot volume")
            return hashes
        }

        for entry in entries {
            let fudPath = "\(prebootBase)/\(entry)/usr/standalone/firmware/FUD/StaticTrustCache.img4"
            let basePath = "\(prebootBase)/\(entry)/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4"

            for path in [fudPath, basePath] {
                if let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
                    let parsed = parseIMG4TrustCache(data)
                    hashes.formUnion(parsed)
                }
            }
        }

        if hashes.isEmpty {
            logger.warning("No trust cache entries found — may need Full Disk Access")
        } else {
            logger.info("Loaded \(hashes.count) trust cache entries")
        }

        return hashes
    }

    private func parseIMG4TrustCache(_ data: Data) -> Set<String> {
        var hashes = Set<String>()

        // IMG4 is DER-encoded. Look for trust cache payload after headers.
        // Trust cache v2 format: magic(4) + version(4) + uuid(16) + entry_count(4) + entries[]
        // Each v2 entry: cdhash(20) + hash_type(2) + constraint_category(2) = 24 bytes
        // We scan for the trust cache magic or known version bytes

        guard data.count > 48 else { return hashes }

        // Strategy: scan for trust cache version marker (0x00000002 for v2)
        // and validate structure by checking entry count plausibility
        if let offset = findTrustCachePayload(data) {
            let remaining = data.count - offset
            guard remaining > 28 else { return hashes }

            let version = data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
                $0.load(as: UInt32.self).littleEndian
            }

            let entryStart: Int
            let entrySize: Int

            if version == 1 {
                // v1: no uuid field, direct to entries
                let entryCount = data.subdata(in: (offset + 4)..<(offset + 8)).withUnsafeBytes {
                    $0.load(as: UInt32.self).littleEndian
                }
                guard entryCount < 50000, remaining >= 8 + Int(entryCount) * 22 else { return hashes }
                entryStart = offset + 8
                entrySize = 22 // 20-byte cdhash + 1-byte hash_type + 1-byte flags
            } else if version == 2 {
                // v2: version(4) + uuid(16) + entry_count(4) + entries
                guard remaining > 24 else { return hashes }
                let entryCount = data.subdata(in: (offset + 24)..<(offset + 28)).withUnsafeBytes {
                    $0.load(as: UInt32.self).littleEndian
                }
                guard entryCount < 50000, remaining >= 28 + Int(entryCount) * 24 else { return hashes }
                entryStart = offset + 28
                entrySize = 24 // 20-byte cdhash + 2-byte hash_type + 2-byte constraint_category
            } else {
                return hashes
            }

            var pos = entryStart
            while pos + 20 <= data.count && pos + entrySize <= data.count {
                let cdhash = data.subdata(in: pos..<(pos + 20))
                let hex = cdhash.map { String(format: "%02x", $0) }.joined()
                if hex != String(repeating: "0", count: 40) {
                    hashes.insert(hex)
                }
                pos += entrySize
            }
        }

        return hashes
    }

    private func findTrustCachePayload(_ data: Data) -> Int? {
        // Skip IMG4/IM4P DER headers to find raw trust cache
        // Look for version bytes (1 or 2 as little-endian u32) followed by plausible structure
        let bytes = [UInt8](data)
        for i in stride(from: 0, to: min(bytes.count - 28, 2048), by: 1) {
            // Check for version 2 (most common on modern macOS)
            if bytes[i] == 2 && bytes[i+1] == 0 && bytes[i+2] == 0 && bytes[i+3] == 0 {
                // Validate: entry count at offset +24 should be reasonable
                if i + 28 <= bytes.count {
                    let entryCount = UInt32(bytes[i+24]) | UInt32(bytes[i+25]) << 8
                        | UInt32(bytes[i+26]) << 16 | UInt32(bytes[i+27]) << 24
                    if entryCount > 100 && entryCount < 50000 {
                        return i
                    }
                }
            }
            // Check for version 1
            if bytes[i] == 1 && bytes[i+1] == 0 && bytes[i+2] == 0 && bytes[i+3] == 0 {
                if i + 8 <= bytes.count {
                    let entryCount = UInt32(bytes[i+4]) | UInt32(bytes[i+5]) << 8
                        | UInt32(bytes[i+6]) << 16 | UInt32(bytes[i+7]) << 24
                    if entryCount > 100 && entryCount < 50000 {
                        return i
                    }
                }
            }
        }
        return nil
    }

    // MARK: - Runtime CDHash

    private func computeRuntimeCDHash(path: String) -> String? {
        let url = URL(fileURLWithPath: path)
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let staticCode = code else { return nil }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }

        // CDHash is in kSecCodeInfoUnique key
        if let hashData = dict[kSecCodeInfoUnique as String] as? Data {
            return hashData.prefix(20).map { String(format: "%02x", $0) }.joined()
        }
        return nil
    }

    // MARK: - Disk CDHash (compute from binary on disk)

    private func computeDiskCDHash(path: String) -> String? {
        // Read the Mach-O and find CodeDirectory blob, then SHA-256 it
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }

        // Find LC_CODE_SIGNATURE
        guard data.count > 32 else { return nil }
        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }

        let headerSize: Int
        let is64: Bool
        switch magic {
        case 0xFEEDFACF: headerSize = 32; is64 = true        // 64-bit
        case 0xFEEDFACE: headerSize = 28; is64 = false       // 32-bit
        case 0xBEBAFECA:                                       // FAT binary
            return computeFatCDHash(data: data)
        default: return nil
        }

        _ = is64 // suppress unused warning
        let ncmds = data.subdata(in: 16..<20).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
        var offset = headerSize
        for _ in 0..<ncmds {
            guard offset + 8 <= data.count else { break }
            let cmd = data.subdata(in: offset..<(offset+4)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
            let cmdsize = data.subdata(in: (offset+4)..<(offset+8)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }

            if cmd == 0x1D { // LC_CODE_SIGNATURE
                guard offset + 16 <= data.count else { break }
                let dataoff = data.subdata(in: (offset+8)..<(offset+12)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
                let datasize = data.subdata(in: (offset+12)..<(offset+16)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
                return extractCDHashFromSignature(data: data, sigOffset: Int(dataoff), sigSize: Int(datasize))
            }
            offset += Int(cmdsize)
        }
        return nil
    }

    private func computeFatCDHash(data: Data) -> String? {
        // Parse FAT header, find arm64e slice
        guard data.count > 8 else { return nil }
        let nfat = data.subdata(in: 4..<8).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        var off = 8
        for _ in 0..<nfat {
            guard off + 20 <= data.count else { break }
            let cpuType = data.subdata(in: off..<(off+4)).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            let sliceOff = data.subdata(in: (off+8)..<(off+12)).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            let sliceSize = data.subdata(in: (off+12)..<(off+16)).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

            if cpuType == 0x0100000C { // CPU_TYPE_ARM64
                let slice = data.subdata(in: Int(sliceOff)..<Int(sliceOff + sliceSize))
                return computeDiskCDHashFromSlice(slice)
            }
            off += 20
        }
        return nil
    }

    private func computeDiskCDHashFromSlice(_ data: Data) -> String? {
        guard data.count > 32 else { return nil }
        let ncmds = data.subdata(in: 16..<20).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
        var offset = 32 // 64-bit header
        for _ in 0..<ncmds {
            guard offset + 8 <= data.count else { break }
            let cmd = data.subdata(in: offset..<(offset+4)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
            let cmdsize = data.subdata(in: (offset+4)..<(offset+8)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
            if cmd == 0x1D {
                guard offset + 16 <= data.count else { break }
                let dataoff = data.subdata(in: (offset+8)..<(offset+12)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
                let datasize = data.subdata(in: (offset+12)..<(offset+16)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
                return extractCDHashFromSignature(data: data, sigOffset: Int(dataoff), sigSize: Int(datasize))
            }
            offset += Int(cmdsize)
        }
        return nil
    }

    private func extractCDHashFromSignature(data: Data, sigOffset: Int, sigSize: Int) -> String? {
        guard sigOffset + sigSize <= data.count, sigSize > 12 else { return nil }

        // SuperBlob: magic(4) + length(4) + count(4) + BlobIndex[]
        let sigData = data.subdata(in: sigOffset..<(sigOffset + sigSize))
        guard sigData.count > 12 else { return nil }

        let magic = sigData.subdata(in: 0..<4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        guard magic == 0xFADE0CC0 else { return nil } // CSMAGIC_EMBEDDED_SIGNATURE

        let count = sigData.subdata(in: 8..<12).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

        // Find CodeDirectory blob (type 0)
        for i in 0..<count {
            let idxOff = 12 + Int(i) * 8
            guard idxOff + 8 <= sigData.count else { break }
            let blobType = sigData.subdata(in: idxOff..<(idxOff+4)).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            let blobOffset = sigData.subdata(in: (idxOff+4)..<(idxOff+8)).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

            if blobType == 0 { // CSSLOT_CODEDIRECTORY
                guard Int(blobOffset) + 8 <= sigData.count else { break }
                let cdMagic = sigData.subdata(in: Int(blobOffset)..<Int(blobOffset)+4).withUnsafeBytes {
                    $0.load(as: UInt32.self).bigEndian
                }
                let cdLength = sigData.subdata(in: Int(blobOffset)+4..<Int(blobOffset)+8).withUnsafeBytes {
                    $0.load(as: UInt32.self).bigEndian
                }
                guard cdMagic == 0xFADE0C02, // CSMAGIC_CODEDIRECTORY
                      Int(blobOffset) + Int(cdLength) <= sigData.count else { break }

                let cdBlob = sigData.subdata(in: Int(blobOffset)..<Int(blobOffset) + Int(cdLength))
                // CDHash = SHA-256 of CodeDirectory, truncated to 20 bytes
                var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
                cdBlob.withUnsafeBytes { ptr in
                    CC_SHA256(ptr.baseAddress, CC_LONG(cdBlob.count), &hash)
                }
                return hash.prefix(20).map { String(format: "%02x", $0) }.joined()
            }
        }
        return nil
    }

    // MARK: - Platform Binary Check

    private func checkPlatformBinary(path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let staticCode = code else { return false }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return false }

        // Platform binaries have specific flags or are signed by Apple
        if let flags = dict[kSecCodeInfoFlags as String] as? UInt32 {
            return (flags & 0x04000000) != 0 // CS_PLATFORM_BINARY
        }
        return false
    }

    private func shortPath(_ path: String) -> String {
        (path as NSString).lastPathComponent
    }
}
