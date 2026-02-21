import Foundation

/// Mirror of EndpointXPCProtocol for use from IrisSecurity package.
/// XPC dispatch is selector-based — protocol name doesn't matter,
/// only method signatures must match exactly.
@objc protocol ESXPCBridge {
  func getSecurityEventsSince(
    _ sinceSeq: UInt64, limit: Int,
    reply: @escaping (UInt64, [Data]) -> Void)
  func getRecentEvents(limit: Int, reply: @escaping ([Data]) -> Void)
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
  let parentPath: String?
  let parentName: String?
  let sequenceNumber: UInt64
}

enum RawESEventType: String, Codable {
  case fileOpen, fileWrite, fileUnlink, fileRename, fileSetExtattr
  case setuid, setgid, sudo
  case remoteThreadCreate, getTask, ptrace
  case kextLoad, mount, tccModify, xpcConnect, btmLaunchItemAdd
  case csInvalidated, signalSent
  case sshLogin, xprotectMalwareDetected
  case authExec, authOpen
  case mmap, mprotect, procSuspendResume
  // Nation-state detection events
  case iokitOpen, copyfile, chown
  case uipcBind, uipcConnect
  case authentication, sessionLogin, sessionLogout
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
    if let pp = parentPath, !pp.isEmpty {
      // Pre-resolved at event creation time (reliable — parent was alive)
      fields["parent_path"] = pp
      fields["parent_name"] = parentName ?? (pp as NSString).lastPathComponent
    } else if process.ppid > 1 {
      // Fallback: runtime lookup (may fail if parent already exited)
      let pp = ProcessEnumeration.getProcessPath(process.ppid)
      if !pp.isEmpty {
        fields["parent_name"] = (pp as NSString).lastPathComponent
        fields["parent_path"] = pp
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
    case .setuid: return "setuid"
    case .setgid: return "setgid"
    case .sudo: return "sudo"
    case .remoteThreadCreate: return "remote_thread_create"
    case .getTask: return "get_task"
    case .ptrace: return "ptrace"
    case .kextLoad: return "kext_load"
    case .mount: return "mount"
    case .tccModify: return "tcc_modify"
    case .xpcConnect: return "xpc_connect"
    case .btmLaunchItemAdd: return "btm_launch_item_add"
    case .sshLogin: return "ssh_login"
    case .xprotectMalwareDetected: return "xprotect_malware"
    case .authExec: return "auth_exec"
    case .authOpen: return "auth_open"
    case .csInvalidated: return "cs_invalidated"
    case .signalSent: return "signal_sent"
    case .mmap: return "mmap"
    case .mprotect: return "mprotect"
    case .procSuspendResume: return "proc_suspend_resume"
    // Nation-state detection events
    case .iokitOpen: return "iokit_open"
    case .copyfile: return "copyfile"
    case .chown: return "chown"
    case .uipcBind: return "uipc_bind"
    case .uipcConnect: return "uipc_connect"
    case .authentication: return "authentication"
    case .sessionLogin: return "session_login"
    case .sessionLogout: return "session_logout"
    }
  }
}

// MARK: - Process Lifecycle Event Decoding

/// Mirrors ESProcessEvent from IrisEndpointExtension for XPC decoding.
struct RawProcessEvent: Codable {
  let eventType: RawProcessEventType
  let process: RawESProcess
  let timestamp: Date

  func toSecurityEvent() -> SecurityEvent {
    let isApple = process.codeSigningInfo?.isAppleSigned ?? false
    var fields: [String: String] = [
      "ppid": "\(process.ppid)",
      "uid": "\(process.userId)",
    ]
    if !process.arguments.isEmpty {
      fields["args"] = process.arguments.joined(separator: " ")
    }
    if let sid = process.codeSigningInfo?.signingId {
      fields["signing_id"] = sid
    }
    if let tid = process.codeSigningInfo?.teamId {
      fields["team_id"] = tid
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

enum RawProcessEventType: String, Codable {
  case exec, fork, exit, signal, csInvalidated

  var securityEventType: String {
    switch self {
    case .exec: return "exec"
    case .fork: return "fork"
    case .exit: return "exit"
    case .signal: return "signal"
    case .csInvalidated: return "cs_invalidated"
    }
  }
}
