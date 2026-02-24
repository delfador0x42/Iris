import EndpointSecurity
import Foundation
import os.log

extension ESClient {

  func handleFileOpen(_ message: UnsafePointer<es_message_t>) {
    let path = esStringToSwift(message.pointee.event.open.file.pointee.path)
    guard shouldTrackFilePath(path) else { return }
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.fileOpen, process: info, machTime: mt, targetPath: path)
  }

  func handleFileWrite(_ message: UnsafePointer<es_message_t>) {
    let path = esStringToSwift(message.pointee.event.write.target.pointee.path)
    guard shouldTrackFilePath(path) else { return }
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.fileWrite, process: info, machTime: mt, targetPath: path)
  }

  func handleFileUnlink(_ message: UnsafePointer<es_message_t>) {
    let path = esStringToSwift(message.pointee.event.unlink.target.pointee.path)
    guard shouldTrackFilePath(path) else { return }
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.fileUnlink, process: info, machTime: mt, targetPath: path)
  }

  func handleFileRename(_ message: UnsafePointer<es_message_t>) {
    let sourcePath = esStringToSwift(message.pointee.event.rename.source.pointee.path)
    let destPath: String
    if message.pointee.event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
      destPath = esStringToSwift(message.pointee.event.rename.destination.existing_file.pointee.path)
    } else {
      let dir = esStringToSwift(message.pointee.event.rename.destination.new_path.dir.pointee.path)
      let filename = esStringToSwift(message.pointee.event.rename.destination.new_path.filename)
      destPath = (dir as NSString).appendingPathComponent(filename)
    }
    guard shouldTrackFilePath(sourcePath) || shouldTrackFilePath(destPath) else { return }
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.fileRename, process: info, machTime: mt, targetPath: destPath, detail: "from: \(sourcePath)")
  }

  func handleSetExtattr(_ message: UnsafePointer<es_message_t>) {
    let path = esStringToSwift(message.pointee.event.setextattr.target.pointee.path)
    guard shouldTrackFilePath(path) else { return }
    let mt = message.pointee.mach_time
    let attrName = esStringToSwift(message.pointee.event.setextattr.extattr)
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.fileSetExtattr, process: info, machTime: mt, targetPath: path, detail: attrName)
  }

  // MARK: - File Create (distinct from write — catches empty file creation)

  func handleFileCreate(_ message: UnsafePointer<es_message_t>) {
    let event = message.pointee.event.create
    let path: String
    if event.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
      path = esStringToSwift(event.destination.existing_file.pointee.path)
    } else {
      let dir = esStringToSwift(event.destination.new_path.dir.pointee.path)
      let filename = esStringToSwift(event.destination.new_path.filename)
      path = (dir as NSString).appendingPathComponent(filename)
    }
    guard shouldTrackFilePath(path) else { return }
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.fileCreate, process: info, machTime: mt, targetPath: path)
  }

  // MARK: - Delete Extended Attribute (quarantine bypass detection)

  func handleDeleteExtattr(_ message: UnsafePointer<es_message_t>) {
    let path = esStringToSwift(message.pointee.event.deleteextattr.target.pointee.path)
    guard shouldTrackFilePath(path) else { return }
    let mt = message.pointee.mach_time
    let attrName = esStringToSwift(message.pointee.event.deleteextattr.extattr)
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.deleteExtattr, process: info, machTime: mt, targetPath: path, detail: attrName)
  }

  // MARK: - Hard Link (credential file bypass, persistence)

  func handleLink(_ message: UnsafePointer<es_message_t>) {
    let source = esStringToSwift(message.pointee.event.link.source.pointee.path)
    let dir = esStringToSwift(message.pointee.event.link.target_dir.pointee.path)
    let filename = esStringToSwift(message.pointee.event.link.target_filename)
    let target = (dir as NSString).appendingPathComponent(filename)
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    recordSecurityEvent(.fileLink, process: info, machTime: mt, targetPath: target, detail: "src=\(source)")
  }

  // MARK: - Set Owner (chown — privilege escalation indicator)

  func handleSetOwner(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/") { return }
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let target = esStringToSwift(message.pointee.event.setowner.target.pointee.path)
    let uid = message.pointee.event.setowner.uid
    let gid = message.pointee.event.setowner.gid
    recordSecurityEvent(.setOwner, process: info, machTime: mt, targetPath: target,
                        detail: "uid=\(uid) gid=\(gid)")
  }

  // MARK: - AUTH_OPEN for Credential Files

  func handleAuthOpen(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>) {
    let path = esStringToSwift(message.pointee.event.open.file.pointee.path)
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    let name = (procPath as NSString).lastPathComponent
    let isPlatform = proc.is_platform_binary
    let signingId = esStringToSwift(proc.signing_id)
    let isApple = isPlatform || (signingId.hasPrefix("com.apple.") && esStringToSwift(proc.team_id).isEmpty)

    let decision = ExecPolicy.evaluateOpen(
      path: path, processName: name, processPath: procPath,
      isPlatform: isPlatform, isApple: isApple)

    let effectiveAllow = ExecPolicy.auditMode ? true : decision.allow
    let allowedFlags: UInt32 = effectiveAllow ? 0xFFFFFFFF : 0
    let respondResult = es_respond_flags_result(client, message, allowedFlags, decision.cache)

    if respondResult != ES_RESPOND_RESULT_SUCCESS {
      logger.error("[AUTH] OPEN respond failed: \(respondResult.rawValue)")
    }

    if !decision.allow {
      let mt = message.pointee.mach_time
      let info = extractBasicProcessInfo(from: proc, machTime: mt)
      recordSecurityEvent(.authOpen, process: info, machTime: mt, targetPath: path,
                          detail: "policy=\(decision.reason)")
    }
  }
}
