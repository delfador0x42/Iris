import Foundation

/// Mirror of EndpointXPCProtocol for use from IrisSecurity package.
/// XPC dispatch is selector-based — protocol name doesn't matter,
/// only method signatures must match exactly.
@objc protocol ESXPCBridge {
  func getSecurityEventsSince(
    _ sinceSeq: UInt64, limit: Int,
    reply: @escaping (UInt64, [Data]) -> Void)
}

/// Mirror of ESSecurityEvent from IrisEndpointExtension.
/// Must match the JSON encoding exactly for decoding XPC payloads.
struct RawESEvent: Codable {
  let id: UUID
  let eventType: RawESEventType
  let process: RawESProcess
  let timestamp: Date
  let targetPath: String?
  let targetProcess: RawESProcess?
  let detail: String?
  let sequenceNumber: UInt64
}

enum RawESEventType: String, Codable {
  case fileOpen, fileWrite, fileUnlink, fileRename, fileSetExtattr
  case setuid, setgid, sudo
  case remoteThreadCreate, getTask, ptrace
  case kextLoad, mount, tccModify, xpcConnect, btmLaunchItemAdd
  case sshLogin, xprotectMalwareDetected
  case authExec, authOpen
  case mmap, mprotect, procSuspendResume
}

struct RawESProcess: Codable {
  let pid: Int32
  let ppid: Int32
  let responsiblePid: Int32
  let path: String
  let name: String
  let arguments: [String]
  let userId: UInt32
  let groupId: UInt32
  let codeSigningInfo: RawCodeSign?
  let timestamp: Date
}

struct RawCodeSign: Codable {
  let teamId: String?
  let signingId: String?
  let flags: UInt32
  let isAppleSigned: Bool
  let isPlatformBinary: Bool
}

// MARK: - Conversion to SecurityEvent

extension RawESEvent {
  func toSecurityEvent() -> SecurityEvent {
    let isApple = process.codeSigningInfo?.isAppleSigned ?? false
    var fields: [String: String] = [:]
    if let tp = targetPath { fields["target_path"] = tp }
    if let d = detail { fields["detail"] = d }
    if let tp = targetProcess {
      fields["target_pid"] = "\(tp.pid)"
      fields["target_name"] = tp.name
      fields["target_path_full"] = tp.path
    }
    fields["ppid"] = "\(process.ppid)"
    if process.ppid > 1 {
      let parentPath = ProcessEnumeration.getProcessPath(process.ppid)
      if !parentPath.isEmpty {
        fields["parent_name"] = URL(fileURLWithPath: parentPath).lastPathComponent
        fields["parent_path"] = parentPath
      }
    }
    fields["uid"] = "\(process.userId)"
    if !process.arguments.isEmpty {
      fields["args"] = process.arguments.joined(separator: " ")
    }
    return SecurityEvent(
      source: .endpoint,
      timestamp: timestamp,
      eventType: eventType.securityEventType,
      processName: process.name,
      processPath: process.path,
      pid: process.pid,
      signingId: process.codeSigningInfo?.signingId,
      isAppleSigned: isApple,
      fields: fields)
  }
}

extension RawESEventType {
  var securityEventType: String {
    switch self {
    case .fileOpen: return "file_open"
    case .fileWrite: return "file_write"
    case .fileUnlink: return "file_unlink"
    case .fileRename: return "file_rename"
    case .fileSetExtattr: return "file_setextattr"
    case .setuid: return "privilege_setuid"
    case .setgid: return "privilege_setgid"
    case .sudo: return "privilege_sudo"
    case .remoteThreadCreate: return "inject_remote_thread"
    case .getTask: return "inject_get_task"
    case .ptrace: return "inject_ptrace"
    case .kextLoad: return "system_kext_load"
    case .mount: return "system_mount"
    case .tccModify: return "system_tcc_modify"
    case .xpcConnect: return "system_xpc_connect"
    case .btmLaunchItemAdd: return "persist_btm_add"
    case .sshLogin: return "auth_ssh_login"
    case .xprotectMalwareDetected: return "auth_xprotect"
    case .authExec: return "auth_exec"
    case .authOpen: return "auth_open"
    case .mmap: return "mmap"
    case .mprotect: return "mprotect"
    case .procSuspendResume: return "proc_suspend_resume"
    }
  }
}
