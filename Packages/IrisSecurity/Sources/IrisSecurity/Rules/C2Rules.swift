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

        // SSH login (lateral movement / unauthorized access)
        rules.append(DetectionRule(
            id: "c2_ssh_login",
            name: "SSH login detected",
            eventType: "ssh_login",
            conditions: [],
            severity: .medium,
            mitreId: "T1021.004",
            mitreName: "Remote Services: SSH"
        ))

        // XPC connection by non-system process to privileged service
        rules.append(DetectionRule(
            id: "c2_xpc_priv_connect",
            name: "Non-system XPC connection to privileged service",
            eventType: "xpc_connect",
            conditions: [
                .processNotAppleSigned,
            ],
            severity: .medium,
            mitreId: "T1559",
            mitreName: "Inter-Process Communication"
        ))

        // XProtect malware detection (Apple's built-in signature match)
        rules.append(DetectionRule(
            id: "c2_xprotect_malware",
            name: "XProtect malware signature detected",
            eventType: "xprotect_malware",
            conditions: [],
            severity: .critical,
            mitreId: "T1204",
            mitreName: "User Execution"
        ))

        // DNS exfiltration detected by entropy analysis
        rules.append(DetectionRule(
            id: "c2_dns_exfil",
            name: "DNS exfiltration indicator (high entropy subdomain)",
            eventType: "dns_exfil",
            conditions: [],
            severity: .high,
            mitreId: "T1071.004",
            mitreName: "Application Layer Protocol: DNS"
        ))

        // DGA domain detected
        rules.append(DetectionRule(
            id: "c2_dns_dga",
            name: "Algorithmically-generated domain detected",
            eventType: "dns_dga",
            conditions: [],
            severity: .high,
            mitreId: "T1568.002",
            mitreName: "Dynamic Resolution: Domain Generation Algorithms"
        ))

        return rules
    }
}
