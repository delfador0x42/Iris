import Foundation
import Security
import os.log

/// Verifies code signatures on binaries
public actor SigningVerifier {
    public static let shared = SigningVerifier()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "SigningVerifier")

    /// Verify the signing status of a binary at the given path
    public func verify(_ path: String) -> (status: SigningStatus, identifier: String?, isApple: Bool) {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?

        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return (.unknown, nil, false)
        }

        // Check if valid signature
        let appleReq = "anchor apple" as CFString
        var requirement: SecRequirement?
        SecRequirementCreateWithString(appleReq, [], &requirement)

        if let req = requirement, SecStaticCodeCheckValidity(code, [], req) == errSecSuccess {
            let identifier = extractIdentifier(code)
            return (.apple, identifier, true)
        }

        // Check general validity
        let valid = SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess
        guard valid else {
            // Check if ad-hoc
            var info: CFDictionary?
            SecCodeCopySigningInformation(code, [], &info)
            if let dict = info as? [String: Any],
               let flags = dict[kSecCodeInfoFlags as String] as? UInt32,
               flags & 0x0002 != 0 { // CS_ADHOC
                return (.adHoc, extractIdentifier(code), false)
            }
            return (.invalid, nil, false)
        }

        // Check for Developer ID
        let devIdReq = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6]" as CFString
        var devIdRequirement: SecRequirement?
        SecRequirementCreateWithString(devIdReq, [], &devIdRequirement)

        if let req = devIdRequirement, SecStaticCodeCheckValidity(code, [], req) == errSecSuccess {
            return (.devID, extractIdentifier(code), false)
        }

        // Check for App Store
        let appStoreReq = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9]" as CFString
        var appStoreRequirement: SecRequirement?
        SecRequirementCreateWithString(appStoreReq, [], &appStoreRequirement)

        if let req = appStoreRequirement, SecStaticCodeCheckValidity(code, [], req) == errSecSuccess {
            return (.appStore, extractIdentifier(code), false)
        }

        return (.unsigned, extractIdentifier(code), false)
    }

    private func extractIdentifier(_ code: SecStaticCode) -> String? {
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, [], &info) == errSecSuccess,
              let dict = info as? [String: Any] else {
            return nil
        }
        return dict[kSecCodeInfoIdentifier as String] as? String
    }
}
