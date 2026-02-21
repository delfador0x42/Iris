import EndpointSecurity
import Foundation
import os.log

// MARK: - Process Lifecycle Event Handlers (exec, fork, exit, signal, cs_invalidated)

extension ESClient {

  func handleExec(_ message: UnsafePointer<es_message_t>) {
    let target = message.pointee.event.exec.target.pointee
    let info = extractProcessInfo(from: target, event: message)
    let pid = audit_token_to_pid(target.audit_token)

    processLock.lock()
    processTable[pid] = info
    processLock.unlock()

    recordEvent(.exec, process: info)
    execCount += 1
    logger.debug("[ES] EXEC: \(info.name) (PID \(pid))")
  }

  func handleFork(_ message: UnsafePointer<es_message_t>) {
    let child = message.pointee.event.fork.child.pointee
    let childPid = audit_token_to_pid(child.audit_token)
    let parentPid = child.ppid
    let rpid = audit_token_to_pid(child.responsible_audit_token)
    let responsiblePid = (rpid > 0 && rpid != childPid) ? rpid : 0

    let childPath = esStringToSwift(child.executable.pointee.path)
    let stub = ESProcessInfo(
      pid: childPid, ppid: parentPid, responsiblePid: responsiblePid,
      path: childPath,
      name: (childPath as NSString).lastPathComponent,
      arguments: [],
      userId: audit_token_to_euid(child.audit_token),
      groupId: audit_token_to_egid(child.audit_token),
      codeSigningInfo: extractCodeSigningInfo(from: child),
      timestamp: Date()
    )

    processLock.lock()
    processTable[childPid] = stub
    processLock.unlock()

    recordEvent(.fork, process: stub)
    forkCount += 1
    logger.debug("[ES] FORK: child PID \(childPid) from parent PID \(parentPid)")
  }

  func handleExit(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let pid = audit_token_to_pid(proc.audit_token)

    processLock.lock()
    let exitingProcess = processTable.removeValue(forKey: pid)
    processLock.unlock()

    if let info = exitingProcess {
      recordEvent(.exit, process: info)
    }

    exitCount += 1
    logger.debug("[ES] EXIT: PID \(pid)")
  }

  func handleSignal(_ message: UnsafePointer<es_message_t>) {
    let target = message.pointee.event.signal.target.pointee
    let targetPid = audit_token_to_pid(target.audit_token)
    let sig = message.pointee.event.signal.sig
    // Only record interesting signals: SIGKILL(9), SIGTERM(15), SIGSTOP(17)
    if sig == 9 || sig == 15 || sig == 17 {
      let proc = message.pointee.process.pointee
      let info = extractBasicProcessInfo(from: proc)
      let targetInfo = extractBasicProcessInfo(from: target)
      recordSecurityEvent(
        .signalSent, process: info, targetProcess: targetInfo,
        detail: "sig=\(sig)")
    }
  }

  func handleCSInvalidated(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc)
    let path = esStringToSwift(proc.executable.pointee.path)
    logger.warning("[ES] CS_INVALIDATED: PID \(info.pid) (\(path)) — code signature invalidated")
    recordSecurityEvent(.csInvalidated, process: info, targetPath: path)
  }
}
