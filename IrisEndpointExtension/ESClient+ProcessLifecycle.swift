import EndpointSecurity
import Foundation
import os.log

extension ESClient {

  func handleExec(_ message: UnsafePointer<es_message_t>) {
    let target = message.pointee.event.exec.target.pointee
    let info = extractProcessInfo(from: target, message: message, includeEnvironment: true)

    processLock.lock()
    processTable[info.pid] = info
    processLock.unlock()

    recordEvent(.exec, process: info)
    execCount += 1
  }

  func handleFork(_ message: UnsafePointer<es_message_t>) {
    let child = message.pointee.event.fork.child.pointee
    let stub = extractBasicProcessInfo(from: child, machTime: message.pointee.mach_time)

    processLock.lock()
    processTable[stub.pid] = stub
    processLock.unlock()

    recordEvent(.fork, process: stub)
    forkCount += 1
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
  }

  func handleSignal(_ message: UnsafePointer<es_message_t>) {
    let sig = message.pointee.event.signal.sig
    guard sig == 9 || sig == 15 || sig == 17 else { return }
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let target = message.pointee.event.signal.target.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let targetInfo = extractBasicProcessInfo(from: target, machTime: mt)
    recordSecurityEvent(
      .signalSent, process: info, machTime: mt,
      targetProcess: targetInfo, detail: "sig=\(sig)")
  }

  func handleCSInvalidated(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let mt = message.pointee.mach_time
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.csInvalidated, process: info, machTime: mt, targetPath: info.path)
  }
}
