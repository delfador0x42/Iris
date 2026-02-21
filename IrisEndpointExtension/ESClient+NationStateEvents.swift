import EndpointSecurity
import Foundation
import os.log

/// Handlers for nation-state detection ES events:
/// IOKit access, file copy, Unix domain sockets,
/// authentication, and session login/logout.
extension ESClient {

  // MARK: - IOKit Open (hardware access, USB implants, VM detection)

  func handleIOKitOpen(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    // Filter: only non-system processes (system IOKit access is extremely noisy)
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/") { return }
    let info = extractBasicProcessInfo(from: proc)
    let userClientClass = esStringToSwift(
      message.pointee.event.iokit_open.user_client_class)
    recordSecurityEvent(.iokitOpen, process: info, detail: userClientClass)
  }

  // MARK: - Copyfile (staging, duplication for exfiltration)

  func handleCopyfile(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    // Filter: system processes are noisy
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/") { return }
    let info = extractBasicProcessInfo(from: proc)
    let source = esStringToSwift(message.pointee.event.copyfile.source.pointee.path)
    var targetStr = ""
    if let targetFile = message.pointee.event.copyfile.target_file {
      targetStr = esStringToSwift(targetFile.pointee.path)
    }
    let targetDir = esStringToSwift(
      message.pointee.event.copyfile.target_dir.pointee.path)
    let target = targetStr.isEmpty ? targetDir : targetStr
    recordSecurityEvent(
      .copyfile, process: info, targetPath: target, detail: "src=\(source)")
  }

  // MARK: - Chown (ownership manipulation, permission escalation)

  func handleChown(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    // Filter: system processes doing normal ownership management
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/") { return }
    let info = extractBasicProcessInfo(from: proc)
    // CHOWN event exposes target file and new owner IDs.
    // Access via setowner since es_events_t uses that field name.
    recordSecurityEvent(.chown, process: info, detail: "ownership_change")
  }

  // MARK: - UIPC Bind/Connect (Unix domain sockets — covert channels, IPC abuse)

  func handleUIPCBind(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/") { return }
    let info = extractBasicProcessInfo(from: proc)
    let dir = esStringToSwift(message.pointee.event.uipc_bind.dir.pointee.path)
    let filename = esStringToSwift(message.pointee.event.uipc_bind.filename)
    recordSecurityEvent(
      .uipcBind, process: info, targetPath: "\(dir)/\(filename)")
  }

  func handleUIPCConnect(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let procPath = esStringToSwift(proc.executable.pointee.path)
    if procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/") { return }
    let info = extractBasicProcessInfo(from: proc)
    let file = esStringToSwift(message.pointee.event.uipc_connect.file.pointee.path)
    recordSecurityEvent(.uipcConnect, process: info, targetPath: file)
  }

  // MARK: - Authentication (login events — lateral movement detection)

  func handleAuthentication(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc)
    let event = message.pointee.event.authentication.pointee
    let success = event.success
    let typeStr: String
    switch event.type {
    case ES_AUTHENTICATION_TYPE_OD: typeStr = "opendirectory"
    case ES_AUTHENTICATION_TYPE_TOUCHID: typeStr = "touchid"
    case ES_AUTHENTICATION_TYPE_TOKEN: typeStr = "token"
    case ES_AUTHENTICATION_TYPE_AUTO_UNLOCK: typeStr = "auto_unlock"
    default: typeStr = "unknown(\(event.type.rawValue))"
    }
    recordSecurityEvent(
      .authentication, process: info,
      detail: "type=\(typeStr) success=\(success)")
  }

  // MARK: - Session Login/Logout (user presence tracking)

  func handleSessionLogin(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc)
    let event = message.pointee.event.lw_session_login.pointee
    let username = esStringToSwift(event.username)
    recordSecurityEvent(
      .sessionLogin, process: info, detail: "user=\(username)")
  }

  func handleSessionLogout(_ message: UnsafePointer<es_message_t>) {
    let proc = message.pointee.process.pointee
    let info = extractBasicProcessInfo(from: proc)
    let event = message.pointee.event.lw_session_logout.pointee
    let username = esStringToSwift(event.username)
    recordSecurityEvent(
      .sessionLogout, process: info, detail: "user=\(username)")
  }
}
