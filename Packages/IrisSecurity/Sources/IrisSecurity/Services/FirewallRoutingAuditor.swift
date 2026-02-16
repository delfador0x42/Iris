import Foundation
import os.log

/// Audits PF firewall rules, NAT configuration, and routing table.
/// Detects traffic redirection, firewall tampering, and unauthorized NAT.
/// Attackers: disable firewall, add NAT rules for traffic interception.
public actor FirewallRoutingAuditor {
  public static let shared = FirewallRoutingAuditor()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "FirewallRouting")

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: await scanFirewallState())
    anomalies.append(contentsOf: await scanPFRules())
    anomalies.append(contentsOf: await scanRoutingTable())
    anomalies.append(contentsOf: await scanProxySettings())
    return anomalies
  }

  /// Check if Application Layer Firewall is enabled
  private func scanFirewallState() async -> [ProcessAnomaly] {
    let output = await runCommand(
      "/usr/libexec/ApplicationFirewall/socketfilterfw", args: ["--getglobalstate"])
    if output.contains("disabled") {
      return [.filesystem(
        name: "ALF", path: "/usr/libexec/ApplicationFirewall",
        technique: "Firewall Disabled",
        description: "Application Layer Firewall is disabled",
        severity: .medium, mitreID: "T1562.004",
        scannerId: "firewall",
        enumMethod: "socketfilterfw --getglobalstate",
        evidence: [
          "firewall=ALF",
          "state=disabled",
        ]
      )]
    }
    return []
  }

  /// Check PF rules for suspicious NAT/redirect
  private func scanPFRules() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand("/sbin/pfctl", args: ["-sr"])
    for line in output.components(separatedBy: "\n") where !line.isEmpty {
      // Suspicious: rdr (redirect) or nat rules added by non-system
      if line.contains("rdr") || line.contains("nat") {
        anomalies.append(.filesystem(
          name: "pfctl", path: "/etc/pf.conf",
          technique: "PF NAT/Redirect Rule",
          description: "PF rule: \(line.prefix(120))",
          severity: .medium, mitreID: "T1557",
          scannerId: "firewall",
          enumMethod: "pfctl -sr → rule list scan",
          evidence: [
            "rule=\(line.prefix(120))",
            "type=nat/rdr",
          ]
        ))
      }
      // Suspicious: pass rules allowing all traffic
      if line.contains("pass all") || line.contains("pass in all") {
        anomalies.append(.filesystem(
          name: "pfctl", path: "/etc/pf.conf",
          technique: "Permissive Firewall Rule",
          description: "PF allows all: \(line.prefix(120))",
          severity: .medium, mitreID: "T1562.004",
          scannerId: "firewall",
          enumMethod: "pfctl -sr → permissive rule scan",
          evidence: [
            "rule=\(line.prefix(120))",
            "type=pass all",
          ]
        ))
      }
    }
    return anomalies
  }

  /// Check routing table for suspicious routes
  private func scanRoutingTable() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand("/usr/sbin/netstat", args: ["-rn"])
    for line in output.components(separatedBy: "\n") {
      // VPN/tunnel interfaces that could indicate unauthorized tunneling
      let suspiciousIfaces = ["utun", "gif", "stf", "ipsec"]
      for iface in suspiciousIfaces {
        if line.contains(iface) && !line.contains("utun0") && !line.contains("utun1") {
          anomalies.append(.filesystem(
            name: "route", path: "",
            technique: "Suspicious Tunnel Interface",
            description: "Route via tunnel: \(line.trimmingCharacters(in: .whitespaces).prefix(100))",
            severity: .low, mitreID: "T1572",
            scannerId: "firewall",
            enumMethod: "netstat -rn → tunnel interface scan",
            evidence: [
              "interface=\(iface)",
              "route=\(line.trimmingCharacters(in: .whitespaces).prefix(100))",
            ]
          ))
        }
      }
    }
    return anomalies
  }

  /// Check for system-wide proxy settings
  private func scanProxySettings() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand(
      "/usr/sbin/scutil", args: ["--proxy"])
    if output.contains("ProxyAutoConfigEnable : 1") {
      anomalies.append(.filesystem(
        name: "proxy", path: "",
        technique: "PAC Proxy Configured",
        description: "Proxy Auto-Config (PAC) enabled — could intercept traffic",
        severity: .medium, mitreID: "T1557",
        scannerId: "firewall",
        enumMethod: "scutil --proxy → ProxyAutoConfigEnable check",
        evidence: [
          "proxy_type=PAC",
          "enabled=true",
        ]
      ))
    }
    if output.contains("SOCKSEnable : 1") {
      anomalies.append(.filesystem(
        name: "proxy", path: "",
        technique: "SOCKS Proxy Configured",
        description: "SOCKS proxy enabled — could tunnel traffic through attacker",
        severity: .high, mitreID: "T1090",
        scannerId: "firewall",
        enumMethod: "scutil --proxy → SOCKSEnable check",
        evidence: [
          "proxy_type=SOCKS",
          "enabled=true",
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
