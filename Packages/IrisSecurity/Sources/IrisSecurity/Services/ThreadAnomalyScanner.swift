import Foundation
import os.log

/// Detects anomalous thread counts in processes.
/// Injected code (dylib injection, shellcode) often creates extra threads.
/// Compares running process thread counts against expected baselines.
public actor ThreadAnomalyScanner {
  public static let shared = ThreadAnomalyScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "ThreadAnomaly")

  /// Processes that normally have few threads — high count = suspicious
  private static let lowThreadExpected: Set<String> = [
    "cat", "echo", "sleep", "true", "false", "yes", "tee",
    "wc", "sort", "uniq", "head", "tail", "cut",
  ]

  /// Threshold for "too many threads" in a simple process
  private static let simpleProcessMax = 10
  /// Threshold for any process to be flagged as extreme
  private static let extremeThreadCount = 500

  public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    for pid in snapshot.pids {
      let threadCount = getThreadCount(pid: pid)
      guard threadCount > 0 else { continue }
      let name = snapshot.name(for: pid)
      let path = snapshot.path(for: pid)

      if Self.lowThreadExpected.contains(name.lowercased()) && threadCount > Self.simpleProcessMax {
        anomalies.append(.forProcess(
          pid: pid, name: name, path: path,
          technique: "Anomalous Thread Count",
          description: "\(name) has \(threadCount) threads (expected <\(Self.simpleProcessMax))",
          severity: .medium, mitreID: "T1055",
          scannerId: "thread_anomaly",
          enumMethod: "proc_pidinfo(PROC_PIDTASKINFO)",
          evidence: [
            "pid: \(pid)",
            "thread_count: \(threadCount)",
            "expected_max: \(Self.simpleProcessMax)",
            "process: \(name)",
          ]
        ))
      } else if threadCount > Self.extremeThreadCount {
        guard !path.hasPrefix("/System/") else { continue }
        anomalies.append(.forProcess(
          pid: pid, name: name, path: path,
          technique: "Extreme Thread Count",
          description: "\(name) has \(threadCount) threads — possible injection or mining",
          severity: .medium, mitreID: "T1055",
          scannerId: "thread_anomaly",
          enumMethod: "proc_pidinfo(PROC_PIDTASKINFO)",
          evidence: [
            "pid: \(pid)",
            "thread_count: \(threadCount)",
            "threshold: \(Self.extremeThreadCount)",
            "process: \(name)",
          ]
        ))
      }
    }
    return anomalies
  }

  private func getThreadCount(pid: pid_t) -> Int {
    var info = proc_taskinfo()
    let size = MemoryLayout<proc_taskinfo>.size
    let ret = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &info, Int32(size))
    guard ret == size else { return 0 }
    return Int(info.pti_threadnum)
  }
}
