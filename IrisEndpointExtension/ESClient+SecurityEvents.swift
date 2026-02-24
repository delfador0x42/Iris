import EndpointSecurity
import Foundation
import os.log

extension ESClient {

  // MARK: - Privilege Escalation

  func handleSetuid(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.setuid, process: info, machTime: mt, detail: "uid=\(message.pointee.event.setuid.uid)")
  }

  func handleSetgid(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.setgid, process: info, machTime: mt, detail: "gid=\(message.pointee.event.setgid.gid)")
  }

  func handleSudo(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let event = message.pointee.event.sudo.pointee
    recordSecurityEvent(.sudo, process: info, machTime: mt, detail: "success=\(event.success)")
  }

  // MARK: - Code Injection

  func handleRemoteThreadCreate(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let target = message.pointee.event.remote_thread_create.target.pointee
    let targetInfo = extractBasicProcessInfo(from: target, machTime: mt)
    recordSecurityEvent(.remoteThreadCreate, process: info, machTime: mt, targetProcess: targetInfo)
  }

  func handleGetTask(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let target = message.pointee.event.get_task.target.pointee
    let targetInfo = extractBasicProcessInfo(from: target, machTime: mt)
    recordSecurityEvent(.getTask, process: info, machTime: mt, targetProcess: targetInfo)
  }

  func handleGetTaskRead(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let target = message.pointee.event.get_task_read.target.pointee
    let targetInfo = extractBasicProcessInfo(from: target, machTime: mt)
    recordSecurityEvent(.getTaskRead, process: info, machTime: mt, targetProcess: targetInfo)
  }

  func handleGetTaskInspect(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let target = message.pointee.event.get_task_inspect.target.pointee
    let targetInfo = extractBasicProcessInfo(from: target, machTime: mt)
    recordSecurityEvent(.getTaskInspect, process: info, machTime: mt, targetProcess: targetInfo)
  }

  func handleTrace(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let target = message.pointee.event.trace.target.pointee
    let targetInfo = extractBasicProcessInfo(from: target, machTime: mt)
    recordSecurityEvent(.ptrace, process: info, machTime: mt, targetProcess: targetInfo)
  }

  // MARK: - Memory/Execution

  func handleMmap(_ message: UnsafePointer<es_message_t>) {
    let event = message.pointee.event.mmap
    let prot = event.protection
    guard prot & 0x04 != 0 else { return }
    let sourcePath = esStringToSwift(event.source.pointee.path)
    if sourcePath.hasPrefix("/System/") || sourcePath.hasPrefix("/usr/lib/") { return }
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let detail = String(format: "prot=0x%x max=0x%x flags=0x%x", prot, event.max_protection, event.flags)
    recordSecurityEvent(.mmap, process: info, machTime: mt, targetPath: sourcePath, detail: detail)
  }

  func handleMprotect(_ message: UnsafePointer<es_message_t>) {
    let event = message.pointee.event.mprotect
    let prot = event.protection
    guard prot & 0x04 != 0 else { return }
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/lib/") { return }
    let mt = message.pointee.mach_time
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let detail = String(format: "prot=0x%x addr=0x%llx size=0x%llx", prot, event.address, event.size)
    recordSecurityEvent(.mprotect, process: info, machTime: mt, detail: detail)
  }

  func handleAuthMprotect(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>) {
    let event = message.pointee.event.mprotect
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)

    let decision = ExecPolicy.evaluateMprotect(
      path: procPath, protection: event.protection, isPlatform: proc.is_platform_binary)
    let effectiveAllow = ExecPolicy.auditMode ? true : decision.allow
    let result: es_auth_result_t = effectiveAllow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
    let respondResult = es_respond_auth_result(client, message, result, decision.cache)

    if respondResult != ES_RESPOND_RESULT_SUCCESS {
      logger.error("[AUTH] MPROTECT respond failed: \(respondResult.rawValue)")
    }
    if !decision.allow {
      let mt = message.pointee.mach_time
      let info = extractBasicProcessInfo(from: proc, machTime: mt)
      let detail = String(format: "policy=%@ prot=0x%x addr=0x%llx", decision.reason, event.protection, event.address)
      recordSecurityEvent(.mprotect, process: info, machTime: mt, detail: detail)
    }
  }

  func handleProcSuspendResume(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let event = message.pointee.event.proc_suspend_resume
    let typeStr: String
    switch event.type {
    case ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND: typeStr = "suspend"
    case ES_PROC_SUSPEND_RESUME_TYPE_RESUME: typeStr = "resume"
    case ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS: typeStr = "shutdown_sockets"
    default: typeStr = "unknown(\(event.type.rawValue))"
    }
    var targetInfo: ESProcessInfo? = nil
    if let target = event.target {
      targetInfo = extractBasicProcessInfo(from: target.pointee, machTime: mt)
    }
    recordSecurityEvent(.procSuspendResume, process: info, machTime: mt, targetProcess: targetInfo, detail: typeStr)
  }

  // MARK: - Process Introspection (anti-debug/monitoring detection)

  func handleProcCheck(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    // Filter system processes
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/") { return }
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    var targetInfo: ESProcessInfo? = nil
    if let target = message.pointee.event.proc_check.target {
      targetInfo = extractBasicProcessInfo(from: target.pointee, machTime: mt)
    }
    let flavor = message.pointee.event.proc_check.flavor
    recordSecurityEvent(.procCheck, process: info, machTime: mt, targetProcess: targetInfo,
                        detail: "flavor=\(flavor)")
  }

  // MARK: - PTY (interactive session tracking)

  func handlePTYGrant(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.ptyGrant, process: info, machTime: mt)
  }

  func handlePTYClose(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.ptyClose, process: info, machTime: mt)
  }

  // MARK: - System Changes

  func handleKextLoad(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let kextId = esStringToSwift(message.pointee.event.kextload.identifier)
    recordSecurityEvent(.kextLoad, process: info, machTime: mt, detail: kextId)
  }

  func handleMount(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let statfs = message.pointee.event.mount.statfs.pointee
    let mountPoint = withUnsafePointer(to: statfs.f_mntonname) { ptr in
      ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
    }
    recordSecurityEvent(.mount, process: info, machTime: mt, targetPath: mountPoint)
  }

  func handleBTMLaunchItemAdd(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let event = message.pointee.event.btm_launch_item_add.pointee
    let execPath = esStringToSwift(event.executable_path)
    let itemUrl = esStringToSwift(event.item.pointee.item_url)
    recordSecurityEvent(.btmLaunchItemAdd, process: info, machTime: mt, targetPath: execPath, detail: itemUrl)
  }

  func handleXPCConnect(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let event = message.pointee.event.xpc_connect.pointee
    recordSecurityEvent(.xpcConnect, process: info, machTime: mt, detail: esStringToSwift(event.service_name))
  }

  func handleTCCModify(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let event = message.pointee.event.tcc_modify.pointee
    let service = esStringToSwift(event.service)
    let identity = esStringToSwift(event.identity)
    recordSecurityEvent(.tccModify, process: info, machTime: mt, detail: "svc=\(service) id=\(identity)")
  }

  // MARK: - Authentication

  func handleSSHLogin(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let event = message.pointee.event.openssh_login.pointee
    let addr = esStringToSwift(event.source_address)
    recordSecurityEvent(.sshLogin, process: info, machTime: mt, detail: "addr=\(addr) success=\(event.success)")
  }

  func handleXProtectMalware(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let event = message.pointee.event.xp_malware_detected.pointee
    let sig = esStringToSwift(event.signature_version)
    let malware = esStringToSwift(event.malware_identifier)
    recordSecurityEvent(.xprotectMalwareDetected, process: info, machTime: mt, detail: "\(malware) sig=\(sig)")
  }
}
