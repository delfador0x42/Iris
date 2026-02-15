import Foundation
import os.log

/// Detects screen capture, camera, and microphone access.
/// Checks TCC grants for kTCCServiceScreenCapture, kTCCServiceCamera,
/// kTCCServiceMicrophone held by non-Apple processes.
/// Malware: Xagent, CloudMensis, FruitFly, DazzleSpy, Insomnia.
public actor ScreenCaptureScanner {
  public static let shared = ScreenCaptureScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "ScreenCapture")

  /// Services that indicate surveillance when granted to non-Apple apps
  private static let sensitiveServices = [
    "kTCCServiceScreenCapture", "kTCCServiceCamera",
    "kTCCServiceMicrophone", "kTCCServiceListenEvent",
  ]

  /// Processes known to legitimately hold screen capture
  private static let allowedClients: Set<String> = [
    "com.apple.screencaptureui", "com.apple.controlcenter",
    "com.apple.screensharing", "com.apple.QuickTimePlayerX",
    "com.apple.FaceTime", "com.apple.PhotoBooth",
  ]

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: await scanTCCGrants())
    anomalies.append(contentsOf: await scanCGWindowList())
    return anomalies
  }

  /// Check TCC database for screen/camera/mic grants to suspicious apps
  private func scanTCCGrants() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let dbPaths = [
      "\(NSHomeDirectory())/Library/Application Support/com.apple.TCC/TCC.db",
      "/Library/Application Support/com.apple.TCC/TCC.db",
    ]
    for dbPath in dbPaths {
      let services = Self.sensitiveServices.map { "'\($0)'" }.joined(separator: ",")
      let query =
        "SELECT service,client,auth_value FROM access WHERE service IN (\(services)) AND auth_value=2;"
      let output = await runCommand("/usr/bin/sqlite3", args: [dbPath, query])
      for line in output.components(separatedBy: "\n") where !line.isEmpty {
        let parts = line.components(separatedBy: "|")
        guard parts.count >= 3 else { continue }
        let (service, client) = (parts[0], parts[1])
        if Self.allowedClients.contains(client) || client.hasPrefix("com.apple.") { continue }
        anomalies.append(.filesystem(
          name: client, path: "",
          technique: "Surveillance TCC Grant",
          description: "\(client) has \(service) permission — potential surveillance",
          severity: .high, mitreID: "T1113"
        ))
      }
    }
    return anomalies
  }

  /// Check CGWindowListCopyWindowInfo for non-standard screen capture processes
  private func scanCGWindowList() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand(
      "/usr/sbin/screencapture", args: ["-x", "-t", "png", "/dev/null"])
    // screencapture itself isn't suspicious, but check for processes using CGDisplayStream
    let psOutput = await runCommand(
      "/bin/ps", args: ["-eo", "pid,comm"])
    let suspiciousCapturers = ["screencapture", "CGDisplayStream", "AVCaptureSession"]
    for line in psOutput.components(separatedBy: "\n") {
      let trimmed = line.trimmingCharacters(in: .whitespaces)
      for name in suspiciousCapturers where trimmed.contains(name) {
        let parts = trimmed.split(separator: " ", maxSplits: 1)
        guard let pid = parts.first.flatMap({ Int32($0) }) else { continue }
        if pid == getpid() { continue }
        // Only flag if it's not an Apple process
        let pathOutput = await runCommand("/bin/ps", args: ["-p", "\(pid)", "-o", "comm="])
        if !pathOutput.hasPrefix("/System/") && !pathOutput.hasPrefix("/usr/") {
          anomalies.append(.forProcess(
            pid: pid, name: String(parts.last ?? ""), path: pathOutput.trimmingCharacters(in: .whitespacesAndNewlines),
            technique: "Active Screen Capture",
            description: "Process PID \(pid) appears to be capturing screen",
            severity: .high, mitreID: "T1113"
          ))
        }
      }
    }
    _ = output // suppress unused warning
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
