import Foundation
import os.log

/// Audits Mach ports and bootstrap services.
/// Unauthorized Mach services indicate rootkit presence or persistence.
/// Checks for non-Apple bootstrap services and suspicious port holders.
public actor MachPortScanner {
  public static let shared = MachPortScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "MachPort")

  /// Known-good Apple service prefixes
  private static let appleServicePrefixes: Set<String> = [
    "com.apple.", "com.openssh.", "org.ntp.",
  ]

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: await scanBootstrapServices())
    anomalies.append(contentsOf: await scanKernelControlSockets())
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
