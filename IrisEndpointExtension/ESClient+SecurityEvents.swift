import Foundation
import EndpointSecurity
import os.log

/// Handlers for privilege escalation, code injection, system changes,
/// and authentication ES events. macOS 13+ events are pointers in the
/// es_events_t union — access via .pointee before reading fields.
extension ESClient {

    // MARK: - Privilege Escalation

    func handleSetuid(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let newUid = message.pointee.event.setuid.uid
        recordSecurityEvent(.setuid, process: info, detail: "uid=\(newUid)")
    }

    func handleSetgid(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let newGid = message.pointee.event.setgid.gid
        recordSecurityEvent(.setgid, process: info, detail: "gid=\(newGid)")
    }

    func handleSudo(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let event = message.pointee.event.sudo.pointee
        let success = event.success
        recordSecurityEvent(.sudo, process: info, detail: "success=\(success)")
    }

    // MARK: - Code Injection

    func handleRemoteThreadCreate(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let target = message.pointee.event.remote_thread_create.target.pointee
        let targetInfo = extractBasicProcessInfo(from: target)
        recordSecurityEvent(.remoteThreadCreate, process: info, targetProcess: targetInfo)
    }

    func handleGetTask(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let target = message.pointee.event.get_task.target.pointee
        let targetInfo = extractBasicProcessInfo(from: target)
        recordSecurityEvent(.getTask, process: info, targetProcess: targetInfo)
    }

    func handleTrace(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let target = message.pointee.event.trace.target.pointee
        let targetInfo = extractBasicProcessInfo(from: target)
        recordSecurityEvent(.ptrace, process: info, targetProcess: targetInfo)
    }

    // MARK: - System Changes

    func handleKextLoad(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let kextId = esStringToSwift(message.pointee.event.kextload.identifier)
        recordSecurityEvent(.kextLoad, process: info, detail: kextId)
    }

    func handleMount(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let statfs = message.pointee.event.mount.statfs.pointee
        let mountPoint = withUnsafePointer(to: statfs.f_mntonname) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                String(cString: $0)
            }
        }
        recordSecurityEvent(.mount, process: info, targetPath: mountPoint)
    }

    func handleBTMLaunchItemAdd(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let event = message.pointee.event.btm_launch_item_add.pointee
        let execPath = esStringToSwift(event.executable_path)
        let itemUrl = esStringToSwift(event.item.pointee.item_url)
        recordSecurityEvent(.btmLaunchItemAdd, process: info, targetPath: execPath, detail: itemUrl)
    }

    func handleXPCConnect(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let event = message.pointee.event.xpc_connect.pointee
        let serviceName = esStringToSwift(event.service_name)
        recordSecurityEvent(.xpcConnect, process: info, detail: serviceName)
    }

    func handleTCCModify(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let event = message.pointee.event.tcc_modify.pointee
        let service = esStringToSwift(event.service)
        let identity = esStringToSwift(event.identity)
        recordSecurityEvent(.tccModify, process: info, detail: "svc=\(service) id=\(identity)")
    }

    // MARK: - Authentication

    func handleSSHLogin(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let event = message.pointee.event.openssh_login.pointee
        let success = event.success
        let addr = esStringToSwift(event.source_address)
        recordSecurityEvent(.sshLogin, process: info, detail: "addr=\(addr) success=\(success)")
    }

    func handleXProtectMalware(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let event = message.pointee.event.xp_malware_detected.pointee
        let sig = esStringToSwift(event.signature_version)
        let malware = esStringToSwift(event.malware_identifier)
        recordSecurityEvent(.xprotectMalwareDetected, process: info, detail: "\(malware) sig=\(sig)")
    }
}
