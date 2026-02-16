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

  // MARK: - Kernel-level CS info via csops()

  /// Kernel code signing flags for a running process.
  /// These come from the kernel's cs_blob, not from SecCode.
  public struct KernelCSInfo: Sendable {
    public let flags: UInt32
    public let isValid: Bool           // CS_VALID
    public let isHardened: Bool        // CS_RUNTIME
    public let isRestrict: Bool        // CS_RESTRICT
    public let isPlatformBinary: Bool  // CS_PLATFORM_BINARY
    public let isDebugged: Bool        // CS_DEBUGGED
    public let isKillOnInvalid: Bool   // CS_KILL

    public var flagsHex: String { String(format: "0x%08X", flags) }
    public var flagDescriptions: [String] {
      var d: [String] = []
      if isValid { d.append("CS_VALID") }
      if isHardened { d.append("CS_RUNTIME") }
      if isRestrict { d.append("CS_RESTRICT") }
      if isPlatformBinary { d.append("CS_PLATFORM_BINARY") }
      if isDebugged { d.append("CS_DEBUGGED") }
      if isKillOnInvalid { d.append("CS_KILL") }
      if flags & 0x0001 != 0 { d.append("CS_VALID") }
      if flags & 0x0002 != 0 { d.append("CS_ADHOC") }
      if flags & 0x0004 != 0 { d.append("CS_GET_TASK_ALLOW") }
      return Array(Set(d))
    }
  }

  /// Get kernel CS flags for a running PID via csops() syscall.
  public static func kernelCSInfo(pid: pid_t) -> KernelCSInfo? {
    var flags: UInt32 = 0
    // csops(pid, CS_OPS_STATUS, &flags, sizeof(flags))
    let result = csops(pid, 0 /* CS_OPS_STATUS */, &flags, MemoryLayout<UInt32>.size)
    guard result == 0 else { return nil }
    return KernelCSInfo(
      flags: flags,
      isValid: flags & 0x00000001 != 0,        // CS_VALID
      isHardened: flags & 0x00010000 != 0,      // CS_RUNTIME
      isRestrict: flags & 0x00000800 != 0,      // CS_RESTRICT
      isPlatformBinary: flags & 0x04000000 != 0, // CS_PLATFORM_BINARY
      isDebugged: flags & 0x10000000 != 0,       // CS_DEBUGGED
      isKillOnInvalid: flags & 0x00000200 != 0   // CS_KILL
    )
  }
}

// csops() is not in public headers — declare it
@_silgen_name("csops")
private func csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer, _ usersize: Int) -> Int32
