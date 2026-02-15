import Foundation
import Security

/// Native code signing validation using Security.framework.
/// Replaces 4 shell-outs to /usr/bin/codesign across the codebase.
public enum CodeSignValidator {

  /// Signing status for a binary.
  public struct SigningInfo: Sendable {
    public let isSigned: Bool
    public let isValidSignature: Bool
    public let isAppleSigned: Bool
    public let signingIdentifier: String?
    public let teamIdentifier: String?
    public let entitlements: [String: Any]?

    /// True if ad-hoc signed (no team ID, no Apple).
    public var isAdHoc: Bool { isSigned && teamIdentifier == nil && !isAppleSigned }
  }

  /// Validate code signature for a binary at path. Thread-safe, no shell-out.
  public static func validate(path: String) -> SigningInfo {
    let url = URL(fileURLWithPath: path) as CFURL
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url, [], &code) == errSecSuccess,
          let code else {
      return SigningInfo(
        isSigned: false, isValidSignature: false, isAppleSigned: false,
        signingIdentifier: nil, teamIdentifier: nil, entitlements: nil)
    }

    let isValid = SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess

    var info: CFDictionary?
    let flags = SecCSFlags(rawValue: kSecCSSigningInformation
      | kSecCSRequirementInformation | kSecCSInternalInformation)
    SecCodeCopySigningInformation(code, flags, &info)
    let dict = info as? [String: Any] ?? [:]

    let signingId = dict[kSecCodeInfoIdentifier as String] as? String
    let teamId = dict[kSecCodeInfoTeamIdentifier as String] as? String
    let entitlements = dict[kSecCodeInfoEntitlementsDict as String] as? [String: Any]

    // Apple-signed = team is Apple or signing ID starts with com.apple
    let isApple = teamId == "apple" || teamId == "Apple"
      || (signingId?.hasPrefix("com.apple.") ?? false)

    return SigningInfo(
      isSigned: true, isValidSignature: isValid, isAppleSigned: isApple,
      signingIdentifier: signingId, teamIdentifier: teamId,
      entitlements: entitlements)
  }

  /// Check for dangerous entitlements. Returns list of dangerous entitlement keys.
  public static func dangerousEntitlements(path: String) -> [String] {
    guard let ents = validate(path: path).entitlements else { return [] }
    let dangerous = [
      "com.apple.security.get-task-allow",
      "com.apple.security.cs.disable-library-validation",
      "com.apple.security.cs.allow-unsigned-executable-memory",
      "com.apple.security.cs.allow-dyld-environment-variables",
      "com.apple.private.security.no-sandbox",
      "task_for_pid-allow",
      "platform-application",
    ]
    return dangerous.filter { key in
      (ents[key] as? Bool) == true
    }
  }

  /// Deep-verify a .app bundle (equivalent to codesign -v --deep).
  public static func verifyBundle(path: String) -> Bool {
    let url = URL(fileURLWithPath: path) as CFURL
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url, [], &code) == errSecSuccess,
          let code else { return false }
    let flags = SecCSFlags(rawValue: UInt32(kSecCSCheckAllArchitectures)
      | UInt32(kSecCSCheckNestedCode) | UInt32(kSecCSStrictValidate))
    return SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess
  }
}
