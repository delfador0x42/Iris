import Foundation

/// Rules from CloudMensis, Phexia, iWorm, XslCmd, Activator, 3CX, Eleanor.
/// Detects cloud C2, dead drop resolvers, and DNS-based C2.
public enum C2Rules {

    /// Cloud storage API hostnames used for C2/exfiltration
    static let cloudC2Domains = [
        "api.pcloud.com", "content.dropboxapi.com", "api.dropboxapi.com",
        "s3.amazonaws.com", "storage.googleapis.com",
        "graph.microsoft.com", // OneDrive
    ]

    /// Dead drop resolver domains
    static let deadDropDomains = [
        "api.telegram.org", "steamcommunity.com",
        "pastebin.com", "raw.githubusercontent.com",
        "gist.githubusercontent.com",
    ]

    /// Legitimate browsers that connect to these domains normally
    static let browserProcesses = [
        "Safari", "Google Chrome", "Firefox", "Brave Browser",
        "Microsoft Edge", "Opera", "Vivaldi", "Arc",
    ]

    public static func rules() -> [DetectionRule] {
        var rules: [DetectionRule] = []

        // Non-browser connecting to cloud storage APIs (CloudMensis, Eleanor)
        for domain in cloudC2Domains {
            rules.append(DetectionRule(
                id: "c2_cloud_\(domain.replacingOccurrences(of: ".", with: "_"))",
                name: "Non-browser connecting to \(domain)",
                eventType: "connection",
                conditions: [
                    .fieldContains("remote_host", domain),
                    .processNameNotIn(browserProcesses + ["Dropbox", "GoogleDrive", "OneDrive"]),
                    .processNotAppleSigned,
                ],
                severity: .high,
                mitreId: "T1102.002",
                mitreName: "Web Service: Bidirectional Communication"
            ))
        }

        // Dead drop resolvers (Phexia, iWorm, 3CX)
        for domain in deadDropDomains {
            rules.append(DetectionRule(
                id: "c2_deaddrop_\(domain.replacingOccurrences(of: ".", with: "_"))",
                name: "Dead drop resolver: \(domain)",
                eventType: "connection",
                conditions: [
                    .fieldContains("remote_host", domain),
                    .processNotAppleSigned,
                    .processNameNotIn(browserProcesses),
                ],
                severity: .high,
                mitreId: "T1102.001",
                mitreName: "Web Service: Dead Drop Resolver"
            ))
        }

        // DNS TXT record C2 (Activator)
        rules.append(DetectionRule(
            id: "c2_dns_txt",
            name: "DNS TXT record query by non-system process",
            eventType: "dns_query",
            conditions: [
                .fieldEquals("record_type", "TXT"),
                .processNotAppleSigned,
                .processNameNotIn(["mDNSResponder", "configd", "dig", "nslookup"]),
            ],
            severity: .medium,
            mitreId: "T1071.004",
            mitreName: "Application Layer Protocol: DNS"
        ))

        // Tor proxy connections (KeRanger, Keydnap)
        rules.append(DetectionRule(
            id: "c2_tor_proxy",
            name: "Connection to Tor proxy port",
            eventType: "connection",
            conditions: [
                .fieldMatchesRegex("remote_port", "^(9050|9150)$"),
            ],
            severity: .high,
            mitreId: "T1090.003",
            mitreName: "Proxy: Multi-hop Proxy"
        ))

        return rules
    }
}
