import EndpointSecurity
import Foundation
import os.log

/// Nation-state detection: hardware access, file staging, covert channels,
/// authentication tracking, and anti-forensics.
extension ESClient {

  // MARK: - IOKit Open (hardware access, USB implants, VM detection)

  func handleIOKitOpen(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/") { return }
    let mt = message.pointee.mach_time
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let userClientClass = esStringToSwift(message.pointee.event.iokit_open.user_client_class)
    recordSecurityEvent(.iokitOpen, process: info, machTime: mt, detail: userClientClass)
  }

  // MARK: - Copyfile (staging for exfiltration)

  func handleCopyfile(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/") { return }
    let mt = message.pointee.mach_time
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let source = esStringToSwift(message.pointee.event.copyfile.source.pointee.path)
    var targetStr = ""
    if let targetFile = message.pointee.event.copyfile.target_file {
      targetStr = esStringToSwift(targetFile.pointee.path)
    }
    let targetDir = esStringToSwift(message.pointee.event.copyfile.target_dir.pointee.path)
    let target = targetStr.isEmpty ? targetDir : targetStr
    recordSecurityEvent(.copyfile, process: info, machTime: mt, targetPath: target, detail: "src=\(source)")
  }

  // MARK: - UIPC Bind/Connect (Unix domain sockets — covert channels)

  func handleUIPCBind(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/") { return }
    let mt = message.pointee.mach_time
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let dir = esStringToSwift(message.pointee.event.uipc_bind.dir.pointee.path)
    let filename = esStringToSwift(message.pointee.event.uipc_bind.filename)
    recordSecurityEvent(.uipcBind, process: info, machTime: mt, targetPath: "\(dir)/\(filename)")
  }

  func handleUIPCConnect(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/") { return }
    let mt = message.pointee.mach_time
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let file = esStringToSwift(message.pointee.event.uipc_connect.file.pointee.path)
    recordSecurityEvent(.uipcConnect, process: info, machTime: mt, targetPath: file)
  }

  // MARK: - Authentication (lateral movement detection)

  func handleAuthentication(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let event = message.pointee.event.authentication.pointee
    let typeStr: String
    switch event.type {
    case ES_AUTHENTICATION_TYPE_OD: typeStr = "opendirectory"
    case ES_AUTHENTICATION_TYPE_TOUCHID: typeStr = "touchid"
    case ES_AUTHENTICATION_TYPE_TOKEN: typeStr = "token"
    case ES_AUTHENTICATION_TYPE_AUTO_UNLOCK: typeStr = "auto_unlock"
    default: typeStr = "unknown(\(event.type.rawValue))"
    }
    recordSecurityEvent(.authentication, process: info, machTime: mt,
                        detail: "type=\(typeStr) success=\(event.success)")
  }

  // MARK: - Session Login/Logout

  func handleSessionLogin(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let event = message.pointee.event.lw_session_login.pointee
    let username = esStringToSwift(event.username)
    recordSecurityEvent(.sessionLogin, process: info, machTime: mt, detail: "user=\(username)")
  }

  func handleSessionLogout(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let event = message.pointee.event.lw_session_logout.pointee
    let username = esStringToSwift(event.username)
    recordSecurityEvent(.sessionLogout, process: info, machTime: mt, detail: "user=\(username)")
  }

  // MARK: - Anti-Forensics Detection

  func handleTruncate(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/") { return }
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let target = esStringToSwift(message.pointee.event.truncate.target.pointee.path)
    recordSecurityEvent(.fileTruncate, process: info, machTime: mt, targetPath: target)
  }

  func handleUtimes(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    // Timestomping — only non-system processes are interesting
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/") { return }
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let target = esStringToSwift(message.pointee.event.utimes.target.pointee.path)
    recordSecurityEvent(.fileUtimes, process: info, machTime: mt, targetPath: target)
  }

  func handleSetMode(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/") { return }
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let target = esStringToSwift(message.pointee.event.setmode.target.pointee.path)
    let mode = message.pointee.event.setmode.mode
    recordSecurityEvent(.fileSetMode, process: info, machTime: mt, targetPath: target,
                        detail: String(format: "mode=0%o", mode))
  }

  func handleSetFlags(_ message: UnsafePointer<es_message_t>) {
    let mt = message.pointee.mach_time
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/") { return }
    let info = extractBasicProcessInfo(from: proc, machTime: mt)
    let target = esStringToSwift(message.pointee.event.setflags.target.pointee.path)
    let flags = message.pointee.event.setflags.flags
    recordSecurityEvent(.fileSetFlags, process: info, machTime: mt, targetPath: target,
                        detail: String(format: "flags=0x%x", flags))
  }
}
