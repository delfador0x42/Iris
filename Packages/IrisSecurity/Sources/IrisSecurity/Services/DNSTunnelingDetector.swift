import Foundation
import os.log

/// Detects DNS tunneling and exfiltration patterns.
/// High query rate, long subdomain labels, TXT record abuse, entropy analysis.
public actor DNSTunnelingDetector {
    public static let shared = DNSTunnelingDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "DNSTunnel")

    /// Query counts per domain in the current window
    private var queryCounts: [String: Int] = [:]
    private var txtQueryCounts: [String: Int] = [:]
    /// Track subdomain entropy per base domain for tunnel detection
    private var subdomainSamples: [String: [String]] = [:]
    private var windowStart = Date()
    private let windowDuration: TimeInterval = 60 // 1 minute window

    /// Record a DNS query for analysis
    public func recordQuery(domain: String, recordType: String) {
        resetWindowIfNeeded()
        let baseDomain = extractBaseDomain(domain)
        queryCounts[baseDomain, default: 0] += 1
        if recordType == "TXT" {
            txtQueryCounts[baseDomain, default: 0] += 1
        }
        // Keep last 50 subdomain labels for entropy analysis
        let labels = domain.split(separator: ".")
        if labels.count >= 3, let sub = labels.first {
            var samples = subdomainSamples[baseDomain, default: []]
            if samples.count < 50 { samples.append(String(sub)) }
            subdomainSamples[baseDomain] = samples
        }
    }

    /// Analyze current DNS patterns for tunneling indicators
    public func analyze() -> [NetworkAnomaly] {
        var anomalies: [NetworkAnomaly] = []

        for (domain, count) in queryCounts {
            // High query rate to single domain (>100/min)
            if count > 100 {
                anomalies.append(NetworkAnomaly(
                    type: .highVolumeDNS,
                    processName: "DNS",
                    remoteAddress: domain,
                    description: "\(count) queries/min to \(domain) — possible DNS tunneling",
                    severity: .high,
                    connectionCount: count,
                    averageInterval: 0
                ))
            }

            // High TXT query frequency (normal apps rarely use TXT)
            if let txtCount = txtQueryCounts[domain], txtCount > 20 {
                anomalies.append(NetworkAnomaly(
                    type: .dnsTunneling,
                    processName: "DNS",
                    remoteAddress: domain,
                    description: "\(txtCount) TXT queries to \(domain) — DNS C2 indicator",
                    severity: .high,
                    connectionCount: txtCount,
                    averageInterval: 0
                ))
            }

            // High-entropy subdomains = encoded data exfiltration
            if let samples = subdomainSamples[domain], samples.count >= 5 {
                let avgEntropy = samples.reduce(0.0) { $0 + shannonEntropy($1) } / Double(samples.count)
                let avgLen = samples.reduce(0) { $0 + $1.count } / samples.count
                if avgEntropy > 3.5 && avgLen > 15 {
                    anomalies.append(NetworkAnomaly(
                        type: .dnsTunneling,
                        processName: "DNS",
                        remoteAddress: domain,
                        description: "High-entropy subdomains to \(domain) (avg entropy: \(String(format: "%.1f", avgEntropy)), avg len: \(avgLen)) — data exfiltration",
                        severity: .critical,
                        connectionCount: count,
                        averageInterval: 0
                    ))
                }
            }
        }

        return anomalies
    }

    /// Check if a single query looks like DNS exfiltration
    public func checkQuery(domain: String) -> Bool {
        let labels = domain.split(separator: ".")
        guard let subdomain = labels.first else { return false }

        // Long subdomain labels (>30 chars typical of DNS exfil/tunnel)
        if subdomain.count > 30 { return true }

        // High entropy subdomain (random chars = exfil encoding)
        let entropy = shannonEntropy(String(subdomain))
        if entropy > 3.5 && subdomain.count > 15 { return true }

        return false
    }

    private func resetWindowIfNeeded() {
        if Date().timeIntervalSince(windowStart) > windowDuration {
            queryCounts.removeAll()
            txtQueryCounts.removeAll()
            subdomainSamples.removeAll()
            windowStart = Date()
        }
    }

    private func extractBaseDomain(_ domain: String) -> String {
        let parts = domain.split(separator: ".")
        guard parts.count >= 2 else { return domain }
        return parts.suffix(2).joined(separator: ".")
    }

    private func shannonEntropy(_ s: String) -> Double {
        var freq: [Character: Int] = [:]
        for c in s { freq[c, default: 0] += 1 }
        let len = Double(s.count)
        return -freq.values.reduce(0.0) { acc, count in
            let p = Double(count) / len
            return acc + p * log2(p)
        }
    }
}
