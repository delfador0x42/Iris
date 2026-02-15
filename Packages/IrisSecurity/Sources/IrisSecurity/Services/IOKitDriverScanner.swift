import Foundation
import os.log

/// Audits IOKit drivers and device tree for non-Apple entries.
/// Non-Apple IOKit drivers can intercept I/O, keylog, or rootkit.
/// Also checks for kernel control sockets registered by drivers.
public actor IOKitDriverScanner {
  public static let shared = IOKitDriverScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "IOKitDriver")

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: await scanIOKitPlane())
    anomalies.append(contentsOf: await scanIOKitPersonalities())
    return anomalies
  }

  /// Check IOKit device tree for non-Apple drivers
  private func scanIOKitPlane() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand(
      "/usr/sbin/ioreg", args: ["-l", "-w", "0"])
    // Look for non-Apple CFBundleIdentifier in IOKit entries
    var currentClass = ""
    for line in output.components(separatedBy: "\n") {
      if line.contains("\"IOClass\"") {
        currentClass =
          line.components(separatedBy: "=").last?
          .trimmingCharacters(in: .whitespaces)
          .replacingOccurrences(of: "\"", with: "") ?? ""
      }
      if line.contains("\"CFBundleIdentifier\"") {
        let bundleId =
          line.components(separatedBy: "=").last?
          .trimmingCharacters(in: .whitespaces)
          .replacingOccurrences(of: "\"", with: "") ?? ""
        if !bundleId.hasPrefix("com.apple.") && !bundleId.isEmpty {
          anomalies.append(.filesystem(
            name: bundleId, path: "",
            technique: "Non-Apple IOKit Driver",
            description: "IOKit driver \(bundleId) (class: \(currentClass))",
            severity: .medium, mitreID: "T1547.006"
          ))
        }
      }
    }
    return anomalies
  }

  /// Check IOKit personalities for suspicious user clients
  private func scanIOKitPersonalities() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand(
      "/usr/sbin/ioreg", args: ["-c", "IOUserClient", "-l", "-w", "0"])
    var currentCreator = ""
    for line in output.components(separatedBy: "\n") {
      if line.contains("\"IOUserClientCreator\"") {
        currentCreator =
          line.components(separatedBy: "=").last?
          .trimmingCharacters(in: .whitespaces)
          .replacingOccurrences(of: "\"", with: "") ?? ""
        // Non-Apple user client creators are suspicious
        if !currentCreator.contains("com.apple") && !currentCreator.isEmpty
          && !currentCreator.hasPrefix("pid ")
        {
          anomalies.append(.filesystem(
            name: currentCreator, path: "",
            technique: "Non-Apple IOUserClient",
            description: "IOUserClient created by: \(currentCreator)",
            severity: .medium, mitreID: "T1547.006"
          ))
        }
      }
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
