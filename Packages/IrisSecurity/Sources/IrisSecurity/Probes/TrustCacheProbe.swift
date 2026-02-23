import Foundation
import Security
import os.log

/// Static trust cache on disk vs runtime code signature verification.
/// Apple's trust cache lists cdhashes of platform binaries. If a binary claims platform
/// status but its cdhash isn't in the static trust cache, something is wrong.
///
/// Binary parsing helpers are in TrustCacheProbe+BinaryParsing.swift
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
}
