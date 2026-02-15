import Foundation
import os.log

/// Audits network configuration for tampering: DNS resolvers, /etc/hosts, firewall.
/// Covers hunt scripts: dns_hijack, firewall_routing, connections.
public actor NetworkConfigAuditor {
    public static let shared = NetworkConfigAuditor()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "NetworkConfig")

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        anomalies.append(contentsOf: checkEtcHosts())
        anomalies.append(contentsOf: checkCustomResolvers())
        anomalies.append(contentsOf: await checkPromiscuousMode())
        anomalies.append(contentsOf: checkProxySettings())
        return anomalies
    }

    /// Check /etc/hosts for suspicious entries
    private func checkEtcHosts() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        guard let content = try? String(contentsOfFile: "/etc/hosts", encoding: .utf8) else { return result }

        let suspiciousPatterns = ["0.0.0.0 ocsp.apple.com", "0.0.0.0 mesu.apple.com",
                                   "127.0.0.1 ocsp.apple.com", "127.0.0.1 mesu.apple.com"]
        let lines = content.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        let activeLines = lines.filter { !$0.hasPrefix("#") && !$0.isEmpty }

        for pattern in suspiciousPatterns {
            if activeLines.contains(where: { $0.contains(pattern) }) {
                result.append(.filesystem(
                    name: "hosts", path: "/etc/hosts",
                    technique: "Hosts File Tampering",
                    description: "Apple domain blocked in /etc/hosts: \(pattern). May disable security updates or OCSP.",
                    severity: .critical, mitreID: "T1565.001"))
            }
        }

        // Flag if hosts file has many custom entries (>20 non-standard)
        let customEntries = activeLines.filter { !$0.hasPrefix("127.0.0.1\tlocalhost") &&
                                                   !$0.hasPrefix("255.255.255.255") &&
                                                   !$0.hasPrefix("::1") &&
                                                   !$0.hasPrefix("fe80::") }
        if customEntries.count > 20 {
            result.append(.filesystem(
                name: "hosts", path: "/etc/hosts",
                technique: "Large Hosts File",
                description: "\(customEntries.count) custom entries in /etc/hosts. May indicate DNS redirection.",
                severity: .medium, mitreID: "T1565.001"))
        }
        return result
    }

    /// Check /etc/resolver/ for custom DNS resolvers
    private func checkCustomResolvers() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let resolverDir = "/etc/resolver"
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: resolverDir) else { return result }

        for file in files {
            let path = "\(resolverDir)/\(file)"
            result.append(.filesystem(
                name: file, path: path,
                technique: "Custom DNS Resolver",
                description: "Custom DNS resolver configured: /etc/resolver/\(file). DNS queries for '\(file)' domain may be redirected.",
                severity: .medium, mitreID: "T1584.002"))
        }
        return result
    }

    /// Check for network interfaces in promiscuous mode (packet sniffing)
    private func checkPromiscuousMode() async -> [ProcessAnomaly] {
        guard let output = runCmd("/sbin/ifconfig", args: ["-a"]) else { return [] }
        var result: [ProcessAnomaly] = []
        for line in output.split(separator: "\n") where line.contains("PROMISC") {
            let iface = line.split(separator: ":").first.map(String.init) ?? "unknown"
            result.append(.filesystem(
                name: iface, path: "ifconfig",
                technique: "Promiscuous Mode",
                description: "Interface \(iface) in promiscuous mode. May indicate packet capture/sniffing.",
                severity: .high, mitreID: "T1040"))
        }
        return result
    }

    /// Check for proxy settings that may intercept traffic
    private func checkProxySettings() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        guard let output = runCmd("/usr/sbin/networksetup", args: ["-getwebproxy", "Wi-Fi"]) else { return result }
        if output.contains("Enabled: Yes") {
            result.append(.filesystem(
                name: "WebProxy", path: "networksetup",
                technique: "Web Proxy Configured",
                description: "HTTP proxy is enabled on Wi-Fi. Traffic may be intercepted.",
                severity: .medium, mitreID: "T1557"))
        }
        return result
    }

    private func runCmd(_ path: String, args: [String]) -> String? {
        let proc = Process(); proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        let pipe = Pipe(); proc.standardOutput = pipe; proc.standardError = pipe
        try? proc.run(); proc.waitUntilExit()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
    }
}
