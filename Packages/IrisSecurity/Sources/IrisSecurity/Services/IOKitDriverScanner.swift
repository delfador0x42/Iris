import Foundation
import os.log

/// Audits IOKit drivers and device tree for non-Apple entries.
/// Non-Apple IOKit drivers can intercept I/O, keylog, or rootkit.
/// Uses native IOKit framework — no shell-outs.
public actor IOKitDriverScanner {
  public static let shared = IOKitDriverScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "IOKitDriver")

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: scanIOKitPlane())
    anomalies.append(contentsOf: scanUserClients())
    return anomalies
  }

  /// Check IOKit service plane for non-Apple drivers via native API
  private func scanIOKitPlane() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let entries = IOKitRegistryReader.registryEntries(plane: "IOService")
    for entry in entries {
      guard let bundleId = entry["CFBundleIdentifier"] as? String,
            !bundleId.isEmpty, !bundleId.hasPrefix("com.apple.")
      else { continue }
      let ioClass = entry["IOClass"] as? String ?? "unknown"
      anomalies.append(.filesystem(
        name: bundleId, path: "",
        technique: "Non-Apple IOKit Driver",
        description: "IOKit driver \(bundleId) (class: \(ioClass))",
        severity: .medium, mitreID: "T1547.006",
        scannerId: "iokit",
        enumMethod: "IOKitRegistryReader.registryEntries → IOService plane scan",
        evidence: [
          "bundle_id=\(bundleId)",
          "io_class=\(ioClass)",
          "plane=IOService",
        ]
      ))
    }
    return anomalies
  }

  /// Check for non-Apple IOUserClient creators
  private func scanUserClients() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let entries = IOKitRegistryReader.servicesMatching(className: "IOUserClient")
    for entry in entries {
      guard let creator = entry["IOUserClientCreator"] as? String,
            !creator.isEmpty,
            !creator.contains("com.apple"),
            !creator.hasPrefix("pid ")
      else { continue }
      anomalies.append(.filesystem(
        name: creator, path: "",
        technique: "Non-Apple IOUserClient",
        description: "IOUserClient created by: \(creator)",
        severity: .medium, mitreID: "T1547.006",
        scannerId: "iokit",
        enumMethod: "IOKitRegistryReader.servicesMatching → IOUserClient creator scan",
        evidence: [
          "creator=\(creator)",
          "class=IOUserClient",
        ]
      ))
    }
    return anomalies
  }
}
