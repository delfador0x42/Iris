import Foundation
import os.log

/// Detects covert communication channels.
/// ICMP tunneling (ping-based C2), raw socket usage, unusual protocols.
/// Malware: XslCmd (ICMP tunnel), CallistoGroup (custom protocols).
public actor CovertChannelDetector {
  public static let shared = CovertChannelDetector()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "CovertChannel")

  /// Suspicious protocol/port combinations
  private static let covertIndicators: [(port: String, proto: String, desc: String)] = [
    ("4444", "tcp", "Metasploit default handler"),
    ("5555", "tcp", "Common RAT port"),
    ("1337", "tcp", "Leet port — often malware"),
    ("31337", "tcp", "Back Orifice / classic backdoor"),
    ("9050", "tcp", "Tor SOCKS proxy"),
    ("9150", "tcp", "Tor Browser SOCKS"),
    ("8080", "tcp", "HTTP proxy — potential C2 relay"),
  ]

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: await scanICMPTunneling())
    anomalies.append(contentsOf: await scanSuspiciousPorts())
    anomalies.append(contentsOf: await scanRawSockets())
    return anomalies
  }

  /// Detect ICMP tunneling by checking for high-volume ICMP traffic
  private func scanICMPTunneling() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand(
      "/usr/sbin/netstat", args: ["-s", "-p", "icmp"])
    for line in output.components(separatedBy: "\n") {
      if line.contains("messages sent") || line.contains("messages received") {
        let count = line.trimmingCharacters(in: .whitespaces)
          .components(separatedBy: " ").first.flatMap(Int.init) ?? 0
        if count > 10000 {
          anomalies.append(.filesystem(
            name: "ICMP", path: "",
            technique: "ICMP Tunnel Indicator",
            description: "High ICMP volume: \(count) messages — possible ICMP tunneling",
            severity: .high, mitreID: "T1095",
            scannerId: "covert_channel",
            enumMethod: "netstat -s -p icmp → message count",
            evidence: [
              "protocol=ICMP",
              "message_count=\(count)",
              "threshold=10000",
            ]
          ))
        }
      }
    }
    return anomalies
  }

  /// Check for connections on known malicious ports
  private func scanSuspiciousPorts() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand(
      "/usr/sbin/lsof", args: ["-i", "-n", "-P"])
    for line in output.components(separatedBy: "\n") {
      for (port, _, desc) in Self.covertIndicators {
        if line.contains(":\(port)") && line.contains("ESTABLISHED") {
          let parts = line.split(separator: " ", maxSplits: 2)
          let procName = String(parts.first ?? "unknown")
          anomalies.append(.filesystem(
            name: procName, path: "",
            technique: "Suspicious Port Connection",
            description: "\(procName) connected on port \(port): \(desc)",
            severity: .high, mitreID: "T1571",
            scannerId: "covert_channel",
            enumMethod: "lsof -i -n -P → ESTABLISHED connection scan",
            evidence: [
              "process=\(procName)",
              "port=\(port)",
              "indicator=\(desc)",
            ]
          ))
        }
      }
    }
    return anomalies
  }

  /// Detect raw socket usage by non-system processes
  private func scanRawSockets() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand(
      "/usr/sbin/lsof", args: ["-i", "raw", "-n", "-P"])
    for line in output.components(separatedBy: "\n") where !line.isEmpty && !line.hasPrefix("COMMAND") {
      let parts = line.split(separator: " ", maxSplits: 2)
      let procName = String(parts.first ?? "unknown")
      if procName == "ping" || procName == "traceroute" || procName == "mDNSResponder" { continue }
      anomalies.append(.filesystem(
        name: procName, path: "",
        technique: "Raw Socket Usage",
        description: "\(procName) using raw sockets — potential covert channel",
        severity: .high, mitreID: "T1095",
        scannerId: "covert_channel",
        enumMethod: "lsof -i raw -n -P → raw socket enumeration",
        evidence: [
          "process=\(procName)",
          "socket_type=raw",
        ]
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
