import Foundation
import Security
import os.log

/// Verifies code signatures on binaries
public actor SigningVerifier {
    public static let shared = SigningVerifier()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "SigningVerifier")

    /// Verify the signing status of a binary at the given path
    public nonisolated func verify(_ path: String) -> (status: SigningStatus, identifier: String?, isApple: Bool) {
        let result = verifyFull(path)
        return (result.status, result.identifier, result.isApple)
    }

    /// Full verification including Team ID and hardened runtime check
    public nonisolated func verifyFull(_ path: String) -> VerificationResult {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?

        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return VerificationResult(status: .unknown)
        }

        let info = extractSigningInfo(code)

        // Check Apple anchor
        let appleReq = "anchor apple" as CFString
        var requirement: SecRequirement?
        SecRequirementCreateWithString(appleReq, [], &requirement)

        if let req = requirement, SecStaticCodeCheckValidity(code, [], req) == errSecSuccess {
            return VerificationResult(
                status: .apple, identifier: info.identifier, teamID: info.teamID,
                isApple: true, isHardenedRuntime: info.isHardenedRuntime
            )
        }

        // Check general validity with strict validation
        let strictFlags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckNestedCode)
        let strictValid = SecStaticCodeCheckValidity(code, strictFlags, nil) == errSecSuccess
        let basicValid = strictValid || SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess

        guard basicValid else {
            // Check if ad-hoc
            if let flags = info.csFlags, flags & 0x0002 != 0 { // CS_ADHOC
                return VerificationResult(
                    status: .adHoc, identifier: info.identifier, teamID: info.teamID,
                    isHardenedRuntime: info.isHardenedRuntime
                )
            }
            return VerificationResult(status: .invalid)
        }

        // Developer ID
        let devIdReq = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6]" as CFString
        var devIdRequirement: SecRequirement?
        SecRequirementCreateWithString(devIdReq, [], &devIdRequirement)

        if let req = devIdRequirement, SecStaticCodeCheckValidity(code, [], req) == errSecSuccess {
            return VerificationResult(
                status: .devID, identifier: info.identifier, teamID: info.teamID,
                isHardenedRuntime: info.isHardenedRuntime
            )
        }

        // App Store
        let appStoreReq = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9]" as CFString
        var appStoreRequirement: SecRequirement?
        SecRequirementCreateWithString(appStoreReq, [], &appStoreRequirement)

        if let req = appStoreRequirement, SecStaticCodeCheckValidity(code, [], req) == errSecSuccess {
            return VerificationResult(
                status: .appStore, identifier: info.identifier, teamID: info.teamID,
                isHardenedRuntime: info.isHardenedRuntime
            )
        }

        return VerificationResult(
            status: .unsigned, identifier: info.identifier, teamID: info.teamID,
            isHardenedRuntime: info.isHardenedRuntime
        )
    }

    private struct SigningInfo {
        var identifier: String?
        var teamID: String?
        var csFlags: UInt32?
        var isHardenedRuntime: Bool = false
    }

    private nonisolated func extractSigningInfo(_ code: SecStaticCode) -> SigningInfo {
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else {
            return SigningInfo()
        }

        let identifier = dict[kSecCodeInfoIdentifier as String] as? String
        let teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
        let flags = dict[kSecCodeInfoFlags as String] as? UInt32

        // CS_RUNTIME = 0x10000 (hardened runtime)
        let isHardened = flags.map { $0 & 0x10000 != 0 } ?? false

        return SigningInfo(
            identifier: identifier, teamID: teamID,
            csFlags: flags, isHardenedRuntime: isHardened
        )
    }
}
