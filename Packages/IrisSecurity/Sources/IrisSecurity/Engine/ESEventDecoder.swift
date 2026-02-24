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
  let machTime: UInt64?
  let globalSeqNum: UInt64?
  let targetPath: String?
  let targetProcess: RawESProcess?
  let detail: String?
  let parentPath: String?
  let parentName: String?
  let sequenceNumber: UInt64
}

enum RawESEventType: String, Codable {
  case fileOpen, fileWrite, fileUnlink, fileRename, fileSetExtattr
  case fileCreate, fileLink, deleteExtattr, setOwner
  // Anti-forensics
  case fileTruncate, fileUtimes, fileSetMode, fileSetFlags
  case setuid, setgid, sudo
  case remoteThreadCreate, getTask, getTaskRead, getTaskInspect, ptrace
  case kextLoad, mount, tccModify, xpcConnect, btmLaunchItemAdd
  case csInvalidated, signalSent
  case sshLogin, xprotectMalwareDetected
  case authExec, authOpen
  case mmap, mprotect, procSuspendResume
  // Process introspection
  case procCheck, ptyGrant, ptyClose
  // Nation-state detection events
  case iokitOpen, copyfile
  case uipcBind, uipcConnect
  case authentication, sessionLogin, sessionLogout
}

struct RawESProcess: Codable {
  let pid: Int32
  let ppid: Int32
  let originalPpid: Int32?
  let responsiblePid: Int32
  let processGroupId: Int32?
  let sessionId: Int32?
  let path: String
  let name: String
  let cdhash: String?
  let arguments: [String]
  let environment: [String]?
  let userId: UInt32
  let groupId: UInt32
  let codeSigningInfo: RawCodeSign?
  let timestamp: Date
  let machTime: UInt64?
  let startTime: Double?
  let isESClient: Bool?
  let ttyPath: String?
}

struct RawCodeSign: Codable {
  let teamId: String?
  let signingId: String?
  let flags: UInt32
  let isAppleSigned: Bool
  let isPlatformBinary: Bool
}

// MARK: - Direct conversion to Event (no SecurityEvent intermediate)

extension RawESEvent {
  func toEvent() -> Event {
    let proc = ProcessRef(
      pid: process.pid, path: process.path,
      sign: process.codeSigningInfo?.signingId ?? "",
      ppid: process.ppid, uid: process.userId,
      cdhash: process.cdhash ?? "",
      teamId: process.codeSigningInfo?.teamId ?? "")
    return Event(
      id: EventIDGen.shared.next(),
      source: .endpoint,
      severity: mapSeverity(),
      process: proc,
      kind: mapKind(),
      fields: buildFields())
  }

  private func mapKind() -> Kind {
    switch eventType {
    // File operations
    case .fileOpen: return .fileOpen(path: targetPath ?? "", flags: 0)
    case .fileWrite: return .fileWrite(path: targetPath ?? "", entropy: 0)
    case .fileCreate: return .fileCreate(path: targetPath ?? "")
    case .fileUnlink: return .fileUnlink(path: targetPath ?? "")
    case .fileRename:
      let src = detail?.replacingOccurrences(of: "from: ", with: "") ?? ""
      return .fileRename(src: src, dst: targetPath ?? "")
    case .fileSetExtattr: return .fileWrite(path: targetPath ?? "", entropy: 0)
    case .fileLink: return .fileCreate(path: targetPath ?? "")
    case .deleteExtattr: return .antiForensic(op: "delete_extattr", path: targetPath ?? "")
    case .setOwner:
      let uid = Int32(detail?.replacingOccurrences(of: "uid=", with: "")
        .components(separatedBy: " ").first ?? "") ?? 0
      return .privilege(op: "set_owner", uid: uid)
    // Anti-forensics
    case .fileTruncate: return .antiForensic(op: "file_truncate", path: targetPath ?? "")
    case .fileUtimes: return .antiForensic(op: "file_utimes", path: targetPath ?? "")
    case .fileSetMode: return .antiForensic(op: "file_setmode", path: targetPath ?? "")
    case .fileSetFlags: return .antiForensic(op: "file_setflags", path: targetPath ?? "")
    // Privilege escalation
    case .setuid:
      let uid = Int32(detail?.replacingOccurrences(of: "uid=", with: "") ?? "") ?? 0
      return .privilege(op: "setuid", uid: uid)
    case .setgid: return .privilege(op: "setgid", uid: 0)
    case .sudo: return .privilege(op: "sudo", uid: 0)
    case .mprotect: return .privilege(op: "mprotect", uid: 0)
    case .mmap: return .privilege(op: "mmap", uid: 0)
    case .procSuspendResume: return .privilege(op: "proc_suspend_resume", uid: 0)
    // Injection
    case .remoteThreadCreate: return .injection(technique: "remote_thread_create", targetPid: targetProcess?.pid ?? 0)
    case .getTask: return .injection(technique: "get_task", targetPid: targetProcess?.pid ?? 0)
    case .getTaskRead: return .injection(technique: "get_task_read", targetPid: targetProcess?.pid ?? 0)
    case .getTaskInspect: return .injection(technique: "get_task_inspect", targetPid: targetProcess?.pid ?? 0)
    case .ptrace: return .injection(technique: "ptrace", targetPid: targetProcess?.pid ?? 0)
    // Signal
    case .signalSent: return .signal(sig: Int32(detail ?? "") ?? 0, targetPid: targetProcess?.pid ?? 0)
    // Process introspection
    case .procCheck:
      let flavor = Int32(detail?.replacingOccurrences(of: "flavor=", with: "") ?? "") ?? 0
      return .procCheck(targetPid: targetProcess?.pid ?? 0, flavor: flavor)
    case .ptyGrant: return .ptyGrant
    case .ptyClose: return .ptyGrant
    // System changes
    case .kextLoad: return .kextLoad(identifier: detail ?? "")
    case .mount: return .mount(mountPoint: targetPath ?? "")
    case .btmLaunchItemAdd: return .btmLaunchItemAdd(path: targetPath ?? "")
    case .xpcConnect: return .xpcConnect(service: detail ?? "")
    case .tccModify:
      let parts = (detail ?? "").components(separatedBy: " ")
      let svc = parts.first?.replacingOccurrences(of: "svc=", with: "") ?? ""
      let id = parts.count > 1 ? parts[1].replacingOccurrences(of: "id=", with: "") : ""
      return .tccModify(service: svc, identity: id)
    // Auth
    case .sshLogin:
      let d = detail ?? ""
      return .sshLogin(address: d, success: d.contains("success=true"))
    case .xprotectMalwareDetected:
      return .alert(rule: "xprotect", name: "XProtect Malware", mitre: "T1204", detail: detail ?? "", chain: [])
    case .authExec:
      return .authExec(target: targetPath ?? "", allowed: detail?.contains("allow=true") ?? true)
    case .authOpen:
      return .authOpen(target: targetPath ?? "", allowed: true)
    case .csInvalidated: return .csInvalidated
    // Nation-state
    case .iokitOpen: return .antiForensic(op: "iokit_open", path: detail ?? "")
    case .copyfile: return .antiForensic(op: "copyfile", path: targetPath ?? "")
    case .uipcBind: return .antiForensic(op: "uipc_bind", path: targetPath ?? detail ?? "")
    case .uipcConnect: return .antiForensic(op: "uipc_connect", path: detail ?? "")
    case .authentication, .sessionLogin, .sessionLogout:
      return .privilege(op: eventType.rawValue, uid: 0)
    }
  }

  private func mapSeverity() -> Severity {
    switch eventType {
    case .remoteThreadCreate, .getTask, .ptrace: .high
    case .xprotectMalwareDetected, .csInvalidated: .critical
    case .getTaskRead, .getTaskInspect: .medium
    case .setuid, .sudo, .kextLoad, .tccModify, .btmLaunchItemAdd: .high
    case .sshLogin, .setOwner: .high
    case .authExec where detail?.contains("allow=false") == true: .high
    case .signalSent, .mprotect, .mmap, .procSuspendResume: .medium
    case .fileTruncate, .fileUtimes, .fileSetMode, .fileSetFlags: .medium
    case .deleteExtattr, .fileLink: .medium
    default: .info
    }
  }

  private func buildFields() -> [String: String]? {
    var f: [String: String] = [:]
    if let tp = targetPath { f["target_path"] = tp }
    if let d = detail { f["detail"] = d }
    if let tp = targetProcess {
      f["target_pid"] = "\(tp.pid)"
      f["target_name"] = tp.name
      f["target_path_full"] = tp.path
    }
    f["ppid"] = "\(process.ppid)"
    if let pp = parentPath, !pp.isEmpty {
      f["parent_path"] = pp
      f["parent_name"] = parentName ?? (pp as NSString).lastPathComponent
    } else if process.ppid > 1 {
      let pp = ProcessEnumeration.getProcessPath(process.ppid)
      if !pp.isEmpty {
        f["parent_name"] = (pp as NSString).lastPathComponent
        f["parent_path"] = pp
      }
    }
    f["uid"] = "\(process.userId)"
    if !process.arguments.isEmpty { f["args"] = process.arguments.joined(separator: " ") }
    if let c = process.cdhash { f["cdhash"] = c }
    if let t = process.codeSigningInfo?.teamId { f["team_id"] = t }
    if let env = process.environment, !env.isEmpty { f["environment"] = env.joined(separator: "; ") }
    if let opid = process.originalPpid { f["original_ppid"] = "\(opid)" }
    if let sid = process.sessionId { f["session_id"] = "\(sid)" }
    if let pgid = process.processGroupId { f["pgid"] = "\(pgid)" }
    if let tty = process.ttyPath { f["tty"] = tty }
    if let isES = process.isESClient, isES { f["is_es_client"] = "true" }
    if let mt = machTime { f["mach_time"] = "\(mt)" }
    return f.isEmpty ? nil : f
  }
}

// MARK: - Process Lifecycle Event Decoding

/// Mirrors ESProcessEvent from IrisEndpointExtension for XPC decoding.
struct RawProcessEvent: Codable {
  let eventType: RawProcessEventType
  let process: RawESProcess
  let timestamp: Date

  func toEvent() -> Event {
    let proc = ProcessRef(
      pid: process.pid, path: process.path,
      sign: process.codeSigningInfo?.signingId ?? "",
      ppid: process.ppid, uid: process.userId,
      cdhash: process.cdhash ?? "",
      teamId: process.codeSigningInfo?.teamId ?? "")
    let kind: Kind = switch eventType {
    case .exec: .exec(parent: process.ppid, argv: process.arguments)
    case .fork: .fork(child: 0)
    case .exit: .exit(code: 0)
    case .signal: .signal(sig: 0, targetPid: 0)
    case .csInvalidated: .csInvalidated
    }
    var f: [String: String] = [
      "ppid": "\(process.ppid)",
      "uid": "\(process.userId)",
    ]
    if !process.arguments.isEmpty { f["args"] = process.arguments.joined(separator: " ") }
    if let sid = process.codeSigningInfo?.signingId { f["signing_id"] = sid }
    if let tid = process.codeSigningInfo?.teamId { f["team_id"] = tid }
    if let c = process.cdhash { f["cdhash"] = c }
    if let env = process.environment, !env.isEmpty { f["environment"] = env.joined(separator: "; ") }
    if let opid = process.originalPpid { f["original_ppid"] = "\(opid)" }
    if let sid = process.sessionId { f["session_id"] = "\(sid)" }
    if let tty = process.ttyPath { f["tty"] = tty }
    return Event(
      id: EventIDGen.shared.next(),
      source: .endpoint,
      severity: eventType == .csInvalidated ? .critical : .info,
      process: proc,
      kind: kind,
      fields: f.isEmpty ? nil : f)
  }
}

enum RawProcessEventType: String, Codable {
  case exec, fork, exit, signal, csInvalidated
}
