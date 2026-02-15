import Foundation
import Security
import os.log

/// Audits the system certificate store for rogue CAs and trust setting modifications.
/// Rogue CAs enable MITM attacks. Malware like Dok/MaMi install proxy CAs.
/// Covers hunt scripts: certificates.
public actor CertificateAuditor {
    public static let shared = CertificateAuditor()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "CertAudit")

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        anomalies.append(contentsOf: scanUserTrustSettings())
        anomalies.append(contentsOf: scanNonAppleCAs())
        return anomalies
    }

    /// Check user trust settings for certificates marked "always trust"
    private func scanUserTrustSettings() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        guard let output = runCmd("/usr/bin/security", args: ["dump-trust-settings"]) else { return result }

        // Count user-modified trust settings
        let trustEntries = output.components(separatedBy: "Trust Settings")
        let userModified = trustEntries.filter { $0.contains("kSecTrustSettingsResult") }

        if userModified.count > 5 {
            result.append(.filesystem(
                name: "TrustSettings", path: "security:dump-trust-settings",
                technique: "Modified Trust Settings",
                description: "\(userModified.count) user-modified certificate trust settings. May indicate MITM proxy or malware CA.",
                severity: .medium, mitreID: "T1556"))
        }
        return result
    }

    /// Scan for non-Apple root CAs in system keychain
    private func scanNonAppleCAs() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let keychains = ["/Library/Keychains/System.keychain",
                         FileManager.default.homeDirectoryForCurrentUser
                            .appendingPathComponent("Library/Keychains/login.keychain-db").path]

        for keychain in keychains {
            guard let output = runCmd("/usr/bin/security", args: [
                "find-certificate", "-a", "-p", keychain
            ]) else { continue }

            // Parse PEM certificates and check issuers
            let certs = output.components(separatedBy: "-----BEGIN CERTIFICATE-----")
            for cert in certs where cert.contains("-----END CERTIFICATE-----") {
                let pem = "-----BEGIN CERTIFICATE-----" + cert
                // Check for suspicious issuer patterns
                let suspiciousIssuers = ["Proxy", "proxy", "mitmproxy", "Charles",
                                          "Fiddler", "Burp", "ZScaler"]
                for issuer in suspiciousIssuers where pem.lowercased().contains(issuer.lowercased()) {
                    result.append(.filesystem(
                        name: issuer, path: keychain,
                        technique: "Proxy/MITM Certificate",
                        description: "Certificate with '\(issuer)' found in \(URL(fileURLWithPath: keychain).lastPathComponent). May enable traffic interception.",
                        severity: .high, mitreID: "T1557.002"))
                }
            }
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
