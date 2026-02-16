import Foundation
import os.log

/// Detects screen capture, camera, and microphone access.
/// Checks TCC grants for screen/camera/mic held by non-Apple processes.
/// Malware: Xagent, CloudMensis, FruitFly, DazzleSpy, Insomnia.
/// Uses SQLiteReader for TCC queries + ProcessSnapshot for active capture.
public actor ScreenCaptureScanner {
  public static let shared = ScreenCaptureScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "ScreenCapture")

  private static let sensitiveServices = [
    "kTCCServiceScreenCapture", "kTCCServiceCamera",
    "kTCCServiceMicrophone", "kTCCServiceListenEvent",
  ]

  private static let allowedClients: Set<String> = [
    "com.apple.screencaptureui", "com.apple.controlcenter",
    "com.apple.screensharing", "com.apple.QuickTimePlayerX",
    "com.apple.FaceTime", "com.apple.PhotoBooth",
  ]

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: scanTCCGrants())
    anomalies.append(contentsOf: scanActiveCapture())
    return anomalies
  }

  /// Check TCC database for screen/camera/mic grants via SQLiteReader
  private func scanTCCGrants() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let dbPaths = [
      "\(NSHomeDirectory())/Library/Application Support/com.apple.TCC/TCC.db",
      "/Library/Application Support/com.apple.TCC/TCC.db",
    ]
    let services = Self.sensitiveServices.map { "'\($0)'" }.joined(separator: ",")
    let sql = """
      SELECT service,client,auth_value FROM access \
      WHERE service IN (\(services)) AND auth_value=2;
      """

    for dbPath in dbPaths {
      guard let db = SQLiteReader(path: dbPath) else { continue }
      let rows = db.query(sql)
      for row in rows {
        guard row.count >= 3,
              let service = row[0], let client = row[1]
        else { continue }
        if Self.allowedClients.contains(client)
          || client.hasPrefix("com.apple.") { continue }
        anomalies.append(.filesystem(
          name: client, path: "",
          technique: "Surveillance TCC Grant",
          description: "\(client) has \(service) — potential surveillance",
          severity: .high, mitreID: "T1113",
          scannerId: "screen_capture",
          enumMethod: "SQLiteReader → TCC.db access table query (auth_value=2)",
          evidence: [
              "client=\(client)",
              "service=\(service)",
              "tcc_db=\(dbPath)",
              "auth_value=2",
          ]))
      }
    }
    return anomalies
  }

  /// Check for active screen capture processes
  private func scanActiveCapture() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let snapshot = ProcessSnapshot.capture()
    let capturers = ["screencapture", "CGDisplayStream", "AVCaptureSession"]
    for pid in snapshot.pids {
      let name = snapshot.name(for: pid)
      let path = snapshot.path(for: pid)
      guard capturers.contains(where: { name.contains($0) }) else { continue }
      guard pid != getpid() else { continue }
      if !path.hasPrefix("/System/") && !path.hasPrefix("/usr/") {
        anomalies.append(.forProcess(
          pid: pid, name: name, path: path,
          technique: "Active Screen Capture",
          description: "Process PID \(pid) capturing screen",
          severity: .high, mitreID: "T1113",
          scannerId: "screen_capture",
          enumMethod: "ProcessSnapshot.capture → process name match against capture indicators",
          evidence: [
              "pid=\(pid)",
              "name=\(name)",
              "path=\(path)",
          ]))
      }
    }
    return anomalies
  }
}
