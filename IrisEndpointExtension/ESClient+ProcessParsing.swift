import EndpointSecurity
import Foundation
import os.log

/// Private API: process responsibility chain (dyld shared cache)
@_silgen_name("responsibility_get_pid_responsible_for_pid")
func es_responsibility_get_pid_responsible_for_pid(_ pid: pid_t) -> pid_t

extension ESClient {

  // MARK: - Full Process Extraction (EXEC events — includes args + env)

  func extractProcessInfo(
    from process: es_process_t,
    message: UnsafePointer<es_message_t>,
    includeEnvironment: Bool = false
  ) -> ESProcessInfo {
    let pid = audit_token_to_pid(process.audit_token)
    let ppid = process.ppid
    let rpid = audit_token_to_pid(process.responsible_audit_token)
    let responsiblePid = (rpid > 0 && rpid != pid) ? rpid : 0
    let path = esStringToSwift(process.executable.pointee.path)
    let name = (path as NSString).lastPathComponent

    // Arguments
    var arguments: [String] = []
    var exec = message.pointee.event.exec
    let argCount = es_exec_arg_count(&exec)
    arguments.reserveCapacity(Int(argCount))
    for i in 0..<argCount {
      arguments.append(esStringToSwift(es_exec_arg(&exec, i)))
    }

    // Environment: capture DYLD_* and suspicious vars (injection detection)
    var environment: [String]? = nil
    if includeEnvironment {
      let envCount = es_exec_env_count(&exec)
      var suspicious: [String] = []
      for i in 0..<envCount {
        let env = esStringToSwift(es_exec_env(&exec, i))
        if env.hasPrefix("DYLD_") || env.hasPrefix("LD_") ||
           env.hasPrefix("CFNETWORK_") || env.hasPrefix("NSZombie") ||
           env.hasPrefix("MallocStackLogging") || env.hasPrefix("OBJC_") {
          suspicious.append(env)
        }
      }
      if !suspicious.isEmpty { environment = suspicious }
    }

    return makeProcessInfo(
      from: process, pid: pid, ppid: ppid, responsiblePid: responsiblePid,
      path: path, name: name, arguments: arguments, environment: environment,
      machTime: message.pointee.mach_time
    )
  }

  // MARK: - Basic Process Extraction (non-EXEC events — no args/env)

  func extractBasicProcessInfo(
    from process: es_process_t,
    machTime: UInt64? = nil
  ) -> ESProcessInfo {
    let pid = audit_token_to_pid(process.audit_token)
    let ppid = process.ppid
    let rpid = audit_token_to_pid(process.responsible_audit_token)
    let responsiblePid = (rpid > 0 && rpid != pid) ? rpid : 0
    let path = esStringToSwift(process.executable.pointee.path)
    let name = (path as NSString).lastPathComponent

    return makeProcessInfo(
      from: process, pid: pid, ppid: ppid, responsiblePid: responsiblePid,
      path: path, name: name, arguments: [], environment: nil,
      machTime: machTime
    )
  }

  // MARK: - Common Builder

  private func makeProcessInfo(
    from process: es_process_t,
    pid: Int32, ppid: Int32, responsiblePid: Int32,
    path: String, name: String,
    arguments: [String], environment: [String]?,
    machTime: UInt64?
  ) -> ESProcessInfo {
    let uid = audit_token_to_euid(process.audit_token)
    let gid = audit_token_to_egid(process.audit_token)
    let csInfo = extractCodeSigningInfo(from: process)

    // cdhash: 20 bytes → hex string
    let cdhash = extractCdhash(from: process)

    // TTY path (interactive session detection)
    var ttyPath: String? = nil
    if let tty = process.tty {
      let p = esStringToSwift(tty.pointee.path)
      if !p.isEmpty { ttyPath = p }
    }

    // Start time: timeval → seconds since epoch
    let tv = process.start_time
    let startTime = Double(tv.tv_sec) + Double(tv.tv_usec) / 1_000_000.0

    return ESProcessInfo(
      pid: pid, ppid: ppid,
      originalPpid: process.original_ppid,
      responsiblePid: responsiblePid,
      processGroupId: process.group_id,
      sessionId: process.session_id,
      path: path, name: name,
      cdhash: cdhash,
      arguments: arguments,
      environment: environment,
      userId: uid, groupId: gid,
      codeSigningInfo: csInfo,
      timestamp: Date(),
      machTime: machTime,
      startTime: startTime > 0 ? startTime : nil,
      isESClient: process.is_es_client,
      ttyPath: ttyPath
    )
  }

  // MARK: - Code Signing

  func extractCodeSigningInfo(from process: es_process_t) -> ESProcessInfo.CodeSigningInfo {
    let signingId = esStringToSwift(process.signing_id)
    let teamId = esStringToSwift(process.team_id)
    let flags = process.codesigning_flags
    let isPlatform = process.is_platform_binary
    let isApple = isPlatform || (signingId.hasPrefix("com.apple.") && teamId.isEmpty)

    return ESProcessInfo.CodeSigningInfo(
      teamId: teamId.isEmpty ? nil : teamId,
      signingId: signingId.isEmpty ? nil : signingId,
      flags: flags, isAppleSigned: isApple, isPlatformBinary: isPlatform
    )
  }

  // MARK: - Cdhash Extraction

  private func extractCdhash(from process: es_process_t) -> String? {
    let hash = process.cdhash
    // Check if all zeros (unsigned / no cdhash)
    let allZero = hash.0 == 0 && hash.1 == 0 && hash.2 == 0 && hash.3 == 0
    guard !allZero else { return nil }

    // Convert 20-byte tuple to hex string
    let bytes: [UInt8] = [
      hash.0, hash.1, hash.2, hash.3, hash.4,
      hash.5, hash.6, hash.7, hash.8, hash.9,
      hash.10, hash.11, hash.12, hash.13, hash.14,
      hash.15, hash.16, hash.17, hash.18, hash.19,
    ]
    return bytes.map { String(format: "%02x", $0) }.joined()
  }

  // MARK: - String Conversion

  func esStringToSwift(_ token: es_string_token_t) -> String {
    guard token.length > 0, let data = token.data else { return "" }
    let buf = UnsafeRawBufferPointer(start: data, count: token.length)
    return String(bytes: buf, encoding: .utf8) ?? ""
  }

  // MARK: - Process Path

  func getProcessPath(_ pid: pid_t) -> String {
    let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
    defer { buf.deallocate() }
    let len = proc_pidpath(pid, buf, UInt32(MAXPATHLEN))
    guard len > 0 else { return "" }
    return String(cString: buf)
  }

  // MARK: - Code Signing via Security Framework (for seeding)

  func getCodeSigningInfoForPath(_ path: String) -> ESProcessInfo.CodeSigningInfo? {
    var staticCode: SecStaticCode?
    let url = URL(fileURLWithPath: path) as CFURL
    guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
          let code = staticCode else { return nil }

    var info: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
            == errSecSuccess,
          let dict = info as? [String: Any] else { return nil }

    let teamId = dict[kSecCodeInfoTeamIdentifier as String] as? String
    let signingId = dict[kSecCodeInfoIdentifier as String] as? String
    let flags = (dict[kSecCodeInfoFlags as String] as? UInt32) ?? 0
    let isPlatform = (flags & 0x4000) != 0
    let isApple = isPlatform || (signingId?.hasPrefix("com.apple.") == true && teamId == nil)

    return ESProcessInfo.CodeSigningInfo(
      teamId: teamId, signingId: signingId, flags: flags,
      isAppleSigned: isApple, isPlatformBinary: isPlatform
    )
  }

  // MARK: - Audit Token

  func auditTokenForSelf() -> audit_token_t {
    var token = audit_token_t()
    var size = UInt32(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
    let kr = task_info(
      mach_task_self_,
      task_flavor_t(TASK_AUDIT_TOKEN),
      withUnsafeMutablePointer(to: &token) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(size)) { $0 }
      },
      &size
    )
    if kr != KERN_SUCCESS {
      logger.warning("[ES] Failed to get own audit token")
    }
    return token
  }

  // MARK: - Error Description

  func esClientErrorDescription(_ result: es_new_client_result_t) -> String {
    switch result {
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
      return "Missing com.apple.developer.endpoint-security.client entitlement"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
      return "Not permitted — grant Full Disk Access or approve in System Settings"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
      return "Not running as root or system extension"
    case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
      return "Too many ES clients — max reached"
    case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
      return "Internal ES error"
    case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
      return "Invalid argument to es_new_client"
    default:
      return "Unknown error (\(result.rawValue))"
    }
  }
}
