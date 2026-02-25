import Foundation
import os.log

/// Audits Mach ports and bootstrap services.
/// Three detection layers:
/// 1. Bootstrap service enumeration (non-Apple services)
/// 2. Kernel control socket detection (non-Apple kctl)
/// 3. Deep per-process Mach port enumeration (injection detection)
public actor MachPortScanner {
  public static let shared = MachPortScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "MachPort")

  /// Known-good Apple service prefixes
  private static let appleServicePrefixes: Set<String> = [
    "com.apple.", "com.openssh.", "org.ntp.",
  ]

  /// Baseline port counts per binary path (for spike detection)
  private var portBaselines: [String: (avg: Double, max: Int32, samples: Int)] = [:]

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: await scanBootstrapServices())
    anomalies.append(contentsOf: await scanKernelControlSockets())
    return anomalies
  }

  /// Full scan including deep per-process port enumeration.
  /// Called by ScannerRegistry with a ProcessSnapshot.
  public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: await scanBootstrapServices())
    anomalies.append(contentsOf: await scanKernelControlSockets())
    for pid in snapshot.pids {
      guard pid > 0 else { continue }
      let path = snapshot.path(for: pid)
      guard !path.isEmpty else { continue }
      let name = snapshot.name(for: pid)
      anomalies.append(contentsOf: deepPortScan(pid: pid, name: name, path: path))
    }
    return anomalies
  }

  /// Enumerate bootstrap Mach services — contradiction-based detection.
  /// Source 1: launchctl endpoint list (what's registered).
  /// Source 2: Service name prefix (claims Apple identity).
  /// Contradiction: service claims non-Apple identity but that alone isn't suspicious.
  /// Real signal: cross-validate the service name against the endpoint format.
  ///
  /// launchctl print system endpoint format:
  ///   "port-number  flags  service.name"
  /// NOT "service.name => ..." — the old parser was splitting on "=>" which doesn't
  /// exist in endpoint output, extracting the port number as the "service name".
  private func scanBootstrapServices() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand(
      "/bin/launchctl", args: ["print", "system"])
    var inEndpoints = false
    for line in output.components(separatedBy: "\n") {
      let trimmed = line.trimmingCharacters(in: .whitespaces)
      if trimmed.contains("endpoints") { inEndpoints = true; continue }
      if inEndpoints && (trimmed.isEmpty || trimmed.hasPrefix("}")) { inEndpoints = false; continue }
      guard inEndpoints else { continue }

      // Endpoint line format: "PORT  FLAGS  \tSERVICE.NAME"
      // Extract the actual service name (last whitespace-separated component with a dot)
      let components = trimmed.split(whereSeparator: { $0.isWhitespace })
      // Find the component that looks like a reverse-DNS service name (contains a dot)
      guard let serviceName = components.last(where: { $0.contains(".") }).map(String.init) else {
        continue
      }
      guard !serviceName.isEmpty else { continue }

      // Cross-validate: is this service claiming to be Apple?
      let claimsApple = Self.appleServicePrefixes.contains(where: { serviceName.hasPrefix($0) })
      if claimsApple { continue }  // Apple-prefixed services are expected

      // Skip hex addresses and numeric-only entries
      if serviceName.hasPrefix("0x") || serviceName.allSatisfy(\.isNumber) { continue }

      anomalies.append(.filesystem(
        name: serviceName, path: "",
        technique: "Non-Apple Mach Service",
        description: "Bootstrap service: \(serviceName)",
        severity: .medium, mitreID: "T1559.001",
        scannerId: "mach_port",
        enumMethod: "launchctl print system → endpoints parsing",
        evidence: [
            "service: \(serviceName)",
            "domain: system",
        ]
      ))
    }
    return anomalies
  }

  /// Check kernel control sockets (kctl) for non-Apple entries
  private func scanKernelControlSockets() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand(
      "/usr/sbin/netstat", args: ["-an", "-f", "systm"])
    for line in output.components(separatedBy: "\n") {
      if line.contains("kctl") {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        // Non-Apple kernel control sockets are suspicious
        if !trimmed.contains("com.apple") && !trimmed.contains("utun")
          && !trimmed.isEmpty
        {
          anomalies.append(.filesystem(
            name: "kctl", path: "",
            technique: "Non-Apple Kernel Control Socket",
            description: "Kernel control: \(trimmed.prefix(100))",
            severity: .high, mitreID: "T1014",
            scannerId: "mach_port",
            enumMethod: "netstat -an -f systm → kctl filtering",
            evidence: [
                "socket_type: kctl",
                "line: \(String(trimmed.prefix(100)))",
            ]
          ))
        }
      }
    }
    return anomalies
  }

  /// Deep Mach port enumeration via task_for_pid + mach_port_names.
  /// Detects: dead-name accumulation (injection remnants),
  /// port count spikes (baseline deviation), high port counts.
  private func deepPortScan(pid: pid_t, name: String, path: String) -> [ProcessAnomaly] {
    var task: mach_port_t = 0
    guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return [] }
    defer { mach_port_deallocate(mach_task_self_, task) }

    var names: mach_port_name_array_t?
    var types: mach_port_type_array_t?
    var namesCnt: mach_msg_type_number_t = 0
    var typesCnt: mach_msg_type_number_t = 0

    let kr = mach_port_names(task, &names, &namesCnt, &types, &typesCnt)
    guard kr == KERN_SUCCESS, let nameArr = names, let typeArr = types else { return [] }
    defer {
      vm_deallocate(mach_task_self_,
        vm_address_t(Int(bitPattern: UnsafeRawPointer(nameArr))),
        vm_size_t(namesCnt) * vm_size_t(MemoryLayout<mach_port_name_t>.size))
      vm_deallocate(mach_task_self_,
        vm_address_t(Int(bitPattern: UnsafeRawPointer(typeArr))),
        vm_size_t(typesCnt) * vm_size_t(MemoryLayout<mach_port_type_t>.size))
    }

    // MACH_PORT_TYPE_* are C macros, not bridged to Swift
    let portTypeSend: UInt32 = 0x10000
    let portTypeRecv: UInt32 = 0x20000
    let portTypeDead: UInt32 = 0x100000

    var sendCount: Int32 = 0, recvCount: Int32 = 0, deadCount: Int32 = 0
    for i in 0..<Int(namesCnt) {
      let t = typeArr[i]
      if t & portTypeSend != 0 { sendCount += 1 }
      if t & portTypeRecv != 0 { recvCount += 1 }
      if t & portTypeDead != 0 { deadCount += 1 }
    }

    let totalPorts = Int32(namesCnt)
    var anomalies: [ProcessAnomaly] = []

    // Update baseline
    let prev = portBaselines[path]
    let prevAvg = prev?.avg ?? Double(totalPorts)
    let prevMax = prev?.max ?? totalPorts
    let samples = (prev?.samples ?? 0) + 1
    let newAvg = prevAvg + (Double(totalPorts) - prevAvg) / Double(samples)
    portBaselines[path] = (avg: newAvg, max: max(prevMax, totalPorts), samples: samples)

    // Dead-name ports: when a port holder dies, remaining send rights become dead names.
    // Many dead names = port injection remnants or namespace manipulation.
    if deadCount > 20 {
      anomalies.append(.forProcess(
        pid: pid, name: name, path: path,
        technique: "Mach Port Dead Names",
        description: "\(name) has \(deadCount) dead-name Mach ports. May indicate port injection remnants.",
        severity: .medium, mitreID: "T1055",
        scannerId: "mach_port",
        enumMethod: "task_for_pid + mach_port_names()",
        evidence: [
          "pid: \(pid)", "binary: \(path)",
          "total_ports: \(totalPorts)",
          "send: \(sendCount)", "receive: \(recvCount)", "dead_name: \(deadCount)",
        ]))
    }

    // Port count spike after warmup (3+ samples)
    if samples > 2 {
      let deviation = Double(totalPorts) - prevAvg
      let threshold = max(prevAvg * 2.0, 100.0)
      if deviation > threshold {
        anomalies.append(.forProcess(
          pid: pid, name: name, path: path,
          technique: "Mach Port Count Spike",
          description: "\(name) has \(totalPorts) ports (baseline avg \(Int(prevAvg))). Sudden increase may indicate port injection.",
          severity: .high, mitreID: "T1055",
          scannerId: "mach_port",
          enumMethod: "task_for_pid + mach_port_names() + baseline comparison",
          evidence: [
            "pid: \(pid)", "binary: \(path)",
            "current_ports: \(totalPorts)", "baseline_avg: \(Int(prevAvg))",
            "baseline_max: \(prevMax)", "deviation: \(Int(deviation))", "samples: \(samples)",
          ]))
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
