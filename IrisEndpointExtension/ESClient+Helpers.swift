import Foundation
import EndpointSecurity
import os.log

extension ESClient {

    // MARK: - Data Extraction

    /// Extract full process info from an es_process_t (typically the exec target)
    func extractProcessInfo(
        from process: es_process_t,
        event: UnsafeMutablePointer<es_message_t>
    ) -> ESProcessInfo {
        let pid = audit_token_to_pid(process.audit_token)
        let ppid = process.ppid
        let path = esStringToSwift(process.executable.pointee.path)
        let name = URL(fileURLWithPath: path).lastPathComponent

        var arguments: [String] = []
        let argCount = es_exec_arg_count(&event.pointee.event.exec)
        for i in 0..<argCount {
            let arg = es_exec_arg(&event.pointee.event.exec, i)
            arguments.append(esStringToSwift(arg))
        }

        let uid = audit_token_to_euid(process.audit_token)
        let gid = audit_token_to_egid(process.audit_token)
        let csInfo = extractCodeSigningInfo(from: process)

        return ESProcessInfo(
            id: UUID(), pid: pid, ppid: ppid, path: path, name: name,
            arguments: arguments, userId: uid, groupId: gid,
            codeSigningInfo: csInfo, timestamp: Date()
        )
    }

    /// Extract code signing info from es_process_t
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

    /// Convert ES string token to Swift String
    func esStringToSwift(_ token: es_string_token_t) -> String {
        guard token.length > 0, let data = token.data else { return "" }
        return String(bytesNoCopy: UnsafeMutableRawPointer(mutating: data),
                      length: token.length, encoding: .utf8, freeWhenDone: false) ?? ""
    }

    // MARK: - Process Path

    /// Get process path via proc_pidpath
    func getProcessPath(_ pid: pid_t) -> String {
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
        defer { buf.deallocate() }
        let len = proc_pidpath(pid, buf, UInt32(MAXPATHLEN))
        guard len > 0 else { return "" }
        return String(cString: buf)
    }

    // MARK: - Code Signing via Security Framework

    /// Get code signing info for a path (used during process table seeding)
    func getCodeSigningInfoForPath(_ path: String) -> ESProcessInfo.CodeSigningInfo? {
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL

        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return nil }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
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

    /// Get our own audit token for muting
    func auditTokenForSelf() -> audit_token_t {
        var token = audit_token_t()
        var size = UInt32(MemoryLayout<audit_token_t>.size)
        let kr = task_info(
            mach_task_self_,
            task_flavor_t(TASK_AUDIT_TOKEN),
            withUnsafeMutablePointer(to: &token) {
                $0.withMemoryRebound(to: integer_t.self, capacity: Int(size) / MemoryLayout<integer_t>.size) { $0 }
            },
            &size
        )
        if kr != KERN_SUCCESS {
            logger.warning("Failed to get own audit token, using empty token")
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
