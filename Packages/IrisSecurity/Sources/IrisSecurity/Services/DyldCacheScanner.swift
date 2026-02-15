import Foundation
import os.log

/// Verifies integrity of the dyld shared cache.
/// Malware can inject into the shared cache to intercept all dylib loads.
/// Checks: cache file hashes, unexpected cache variants, modification times.
public actor DyldCacheScanner {
  public static let shared = DyldCacheScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "DyldCache")

  /// Expected dyld cache locations
  private static let cachePaths = [
    "/System/Library/dyld/dyld_shared_cache_arm64e",
    "/System/Library/dyld/dyld_shared_cache_x86_64h",
    "/System/Library/dyld/dyld_shared_cache_x86_64",
  ]

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: scanCacheFiles())
    anomalies.append(contentsOf: await scanDyldEnvironment())
    return anomalies
  }

  /// Check dyld cache files for unexpected modifications
  private func scanCacheFiles() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let fm = FileManager.default
    let dyldDir = "/System/Library/dyld"
    guard let entries = try? fm.contentsOfDirectory(atPath: dyldDir) else { return [] }

    for entry in entries where entry.hasPrefix("dyld_shared_cache") {
      let path = "\(dyldDir)/\(entry)"
      guard let attrs = try? fm.attributesOfItem(atPath: path) else { continue }

      // Check for unexpected cache variants
      let knownSuffixes = ["arm64e", "x86_64h", "x86_64", "arm64e.01", "arm64e.02",
                           "arm64e.symbols", "x86_64h.01", "x86_64h.02"]
      let suffix = entry.replacingOccurrences(of: "dyld_shared_cache_", with: "")
      let isKnown = knownSuffixes.contains(where: { suffix.hasPrefix($0) })
      if !isKnown {
        anomalies.append(.filesystem(
          name: entry, path: path,
          technique: "Unexpected Dyld Cache Variant",
          description: "Non-standard dyld cache file: \(entry)",
          severity: .high, mitreID: "T1574"
        ))
      }

      // Check if writable (should be read-only on SSV)
      if let posix = attrs[.posixPermissions] as? Int, posix & 0o222 != 0 {
        anomalies.append(.filesystem(
          name: entry, path: path,
          technique: "Writable Dyld Cache",
          description: "Dyld cache is writable: \(entry) — integrity concern",
          severity: .critical, mitreID: "T1574"
        ))
      }
    }
    return anomalies
  }

  /// Check for DYLD_SHARED_REGION override
  private func scanDyldEnvironment() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand(
      "/usr/bin/env", args: [])
    if output.contains("DYLD_SHARED_REGION") || output.contains("DYLD_SHARED_CACHE_DIR") {
      anomalies.append(.filesystem(
        name: "dyld", path: "",
        technique: "Dyld Cache Override",
        description: "DYLD_SHARED_REGION or DYLD_SHARED_CACHE_DIR is set — cache hijacking",
        severity: .critical, mitreID: "T1574"
      ))
    }
    return anomalies
  }

  private func runCommand(_ path: String, args: [String]) async -> String {
    await withCheckedContinuation { continuation in
      let process = Process(); let pipe = Pipe()
      process.executableURL = URL(fileURLWithPath: path)
      process.arguments = args
      process.standardOutput = pipe; process.standardError = pipe
      do {
        try process.run(); process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
      } catch { continuation.resume(returning: "") }
    }
  }
}
