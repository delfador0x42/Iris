import Foundation
import Security
import os.log

/// Audits the system certificate store for rogue CAs and trust setting modifications.
/// Rogue CAs enable MITM attacks. Malware like Dok/MaMi install proxy CAs.
/// Uses native Security framework — no shell-outs.
public actor CertificateAuditor {
  public static let shared = CertificateAuditor()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "CertAudit")

  public func scan() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: scanUserTrustSettings())
    anomalies.append(contentsOf: scanKeychainCertificates())
    return anomalies
  }

  /// Check user trust settings via SecTrustSettingsCopyCertificates
  private func scanUserTrustSettings() -> [ProcessAnomaly] {
    var result: [ProcessAnomaly] = []

    // Check user domain for manually trusted certs
    var certs: CFArray?
    let status = SecTrustSettingsCopyCertificates(.user, &certs)
    guard status == errSecSuccess, let certArray = certs as? [SecCertificate] else {
      return result
    }

    var suspiciousCount = 0
    for cert in certArray {
      let name = certName(cert)
      var trustSettings: CFArray?
      guard SecTrustSettingsCopyTrustSettings(cert, .user, &trustSettings) == errSecSuccess,
            let settings = trustSettings as? [[String: Any]]
      else { continue }

      // Check if any setting has "always trust" result
      for setting in settings {
        if let resultValue = setting[kSecTrustSettingsResult as String] as? Int,
           resultValue == SecTrustSettingsResult.trustRoot.rawValue
            || resultValue == SecTrustSettingsResult.trustAsRoot.rawValue {
          suspiciousCount += 1

          // Check for known MITM proxy cert names
          let suspiciousNames = ["proxy", "mitmproxy", "charles", "fiddler", "burp", "zscaler"]
          let lower = name.lowercased()
          if suspiciousNames.contains(where: { lower.contains($0) }) {
            result.append(.filesystem(
              name: name, path: "keychain:user-trust-settings",
              technique: "Proxy/MITM Certificate Trusted",
              description: "User-trusted certificate '\(name)' matches known MITM proxy pattern",
              severity: .high, mitreID: "T1557.002",
              scannerId: "certificate",
              enumMethod: "SecTrustSettingsCopyCertificates → user domain trust scan",
              evidence: [
                "cert_name=\(name)",
                "trust_domain=user",
                "matched_pattern=\(lower)",
              ]))
          }
        }
      }
    }

    if suspiciousCount > 5 {
      result.append(.filesystem(
        name: "TrustSettings", path: "keychain:user-trust-settings",
        technique: "Modified Trust Settings",
        description: "\(suspiciousCount) user-modified certificate trust settings. May indicate MITM proxy or malware CA.",
        severity: .medium, mitreID: "T1556",
        scannerId: "certificate",
        enumMethod: "SecTrustSettingsCopyCertificates → user domain trust enumeration",
        evidence: [
          "suspicious_count=\(suspiciousCount)",
          "trust_domain=user",
          "threshold=5",
        ]))
    }

    return result
  }

  /// Scan keychains for certificates with suspicious issuer names
  private func scanKeychainCertificates() -> [ProcessAnomaly] {
    var result: [ProcessAnomaly] = []

    let query: [String: Any] = [
      kSecClass as String: kSecClassCertificate,
      kSecReturnRef as String: true,
      kSecMatchLimit as String: kSecMatchLimitAll,
    ]

    var items: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &items) == errSecSuccess,
          let certs = items as? [SecCertificate]
    else { return result }

    let suspiciousIssuers = ["proxy", "mitmproxy", "charles", "fiddler", "burp", "zscaler"]

    for cert in certs {
      let name = certName(cert)
      let lower = name.lowercased()
      for issuer in suspiciousIssuers where lower.contains(issuer) {
        result.append(.filesystem(
          name: issuer.capitalized, path: "keychain:certificate",
          technique: "Proxy/MITM Certificate",
          description: "Certificate '\(name)' in keychain matches '\(issuer)'. May enable traffic interception.",
          severity: .high, mitreID: "T1557.002",
          scannerId: "certificate",
          enumMethod: "SecItemCopyMatching → keychain certificate enumeration",
          evidence: [
            "cert_name=\(name)",
            "matched_issuer=\(issuer)",
            "source=keychain",
          ]))
      }
    }

    return result
  }

  private func certName(_ cert: SecCertificate) -> String {
    (SecCertificateCopySubjectSummary(cert) as? String) ?? "Unknown"
  }
}
