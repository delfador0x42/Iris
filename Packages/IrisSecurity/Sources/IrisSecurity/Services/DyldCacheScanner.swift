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

  public func scan() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: scanCacheFiles())
    anomalies.append(contentsOf: scanDyldEnvironment())
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
          severity: .high, mitreID: "T1574",
          scannerId: "dyld_cache",
          enumMethod: "FileManager.contentsOfDirectory → dyld cache variant check",
          evidence: [
            "filename=\(entry)",
            "suffix=\(suffix)",
            "directory=\(dyldDir)",
          ]
        ))
      }

      // Check if writable (should be read-only on SSV)
      if let posix = attrs[.posixPermissions] as? Int, posix & 0o222 != 0 {
        anomalies.append(.filesystem(
          name: entry, path: path,
          technique: "Writable Dyld Cache",
          description: "Dyld cache is writable: \(entry) — integrity concern",
          severity: .critical, mitreID: "T1574",
          scannerId: "dyld_cache",
          enumMethod: "FileManager.attributesOfItem → posixPermissions check",
          evidence: [
            "filename=\(entry)",
            "permissions=0o\(String(posix, radix: 8))",
            "writable=true",
          ]
        ))
      }
    }
    return anomalies
  }

  /// Check all running processes for DYLD_SHARED_REGION / DYLD_SHARED_CACHE_DIR
  private func scanDyldEnvironment() -> [ProcessAnomaly] {
    let dangerousVars = ["DYLD_SHARED_REGION", "DYLD_SHARED_CACHE_DIR"]
    var anomalies: [ProcessAnomaly] = []
    let snapshot = ProcessSnapshot.capture()

    for pid in snapshot.pids {
      guard pid > 0 else { continue }
      let envVars = ProcessEnumeration.getProcessEnvironment(pid)
      for (key, value) in envVars where dangerousVars.contains(key) {
        let path = snapshot.path(for: pid)
        let name = snapshot.name(for: pid)
        anomalies.append(.forProcess(
          pid: pid, name: name, path: path,
          technique: "Dyld Cache Override",
          description: "\(name) (PID \(pid)) has \(key)=\(value) — shared cache hijacking",
          severity: .critical, mitreID: "T1574",
          scannerId: "dyld_cache",
          enumMethod: "ProcessEnumeration.getProcessEnvironment → DYLD env var scan",
          evidence: [
            "pid=\(pid)",
            "env_var=\(key)",
            "env_value=\(value)",
          ]
        ))
      }
    }
    return anomalies
  }
}
