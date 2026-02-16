import Foundation
import EndpointSecurity
import os.log

/// Handlers for file operation ES events: OPEN, WRITE, UNLINK, RENAME, SETEXTATTR.
/// These detect credential file access, TCC.db manipulation, ransomware staging,
/// quarantine bypass, and evidence destruction.
extension ESClient {

    func handleFileOpen(_ message: UnsafePointer<es_message_t>) {
        let file = message.pointee.event.open.file.pointee
        let path = esStringToSwift(file.path)
        guard shouldTrackFilePath(path) else { return }

        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        recordSecurityEvent(.fileOpen, process: info, targetPath: path)
    }

    func handleFileWrite(_ message: UnsafePointer<es_message_t>) {
        let target = message.pointee.event.write.target.pointee
        let path = esStringToSwift(target.path)
        guard shouldTrackFilePath(path) else { return }

        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        recordSecurityEvent(.fileWrite, process: info, targetPath: path)
    }

    func handleFileUnlink(_ message: UnsafePointer<es_message_t>) {
        let target = message.pointee.event.unlink.target.pointee
        let path = esStringToSwift(target.path)
        guard shouldTrackFilePath(path) else { return }

        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        recordSecurityEvent(.fileUnlink, process: info, targetPath: path)
    }

    func handleFileRename(_ message: UnsafePointer<es_message_t>) {
        let source = message.pointee.event.rename.source.pointee
        let sourcePath = esStringToSwift(source.path)
        let destPath: String
        let destType = message.pointee.event.rename.destination_type
        if destType == ES_DESTINATION_TYPE_EXISTING_FILE {
            destPath = esStringToSwift(message.pointee.event.rename.destination.existing_file.pointee.path)
        } else {
            let dir = esStringToSwift(message.pointee.event.rename.destination.new_path.dir.pointee.path)
            let filename = esStringToSwift(message.pointee.event.rename.destination.new_path.filename)
            destPath = (dir as NSString).appendingPathComponent(filename)
        }

        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        let detail = "from: \(sourcePath)"
        recordSecurityEvent(.fileRename, process: info, targetPath: destPath, detail: detail)
    }

    func handleSetExtattr(_ message: UnsafePointer<es_message_t>) {
        let target = message.pointee.event.setextattr.target.pointee
        let path = esStringToSwift(target.path)
        let attrName = esStringToSwift(message.pointee.event.setextattr.extattr)

        let proc = message.pointee.process.pointee
        let info = extractBasicProcessInfo(from: proc)
        recordSecurityEvent(.fileSetExtattr, process: info, targetPath: path, detail: attrName)
    }

    // MARK: - Authorization: AUTH_OPEN for Credential Files

    func handleAuthOpen(_ message: UnsafePointer<es_message_t>) {
        let file = message.pointee.event.open.file.pointee
        let path = esStringToSwift(file.path)
        let proc = message.pointee.process.pointee
        let isPlatform = proc.is_platform_binary
        let signingId = esStringToSwift(proc.signing_id)
        let isApple = isPlatform || (signingId.hasPrefix("com.apple.") && esStringToSwift(proc.team_id).isEmpty)
        let name = URL(fileURLWithPath: esStringToSwift(proc.executable.pointee.path)).lastPathComponent

        let decision = ExecPolicy.evaluateOpen(
            path: path, processName: name,
            isPlatform: isPlatform, isApple: isApple
        )

        let effectiveAllow = ExecPolicy.auditMode ? true : decision.allow
        let result: es_auth_result_t = effectiveAllow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY

        guard let client = self.client else { return }
        let respondResult = es_respond_auth_result(client, message, result, decision.cache)

        if respondResult != ES_RESPOND_RESULT_SUCCESS {
            let pid = audit_token_to_pid(proc.audit_token)
            logger.error("[AUTH] Failed to respond AUTH_OPEN for PID \(pid): \(respondResult.rawValue)")
        }

        if !decision.allow {
            let pid = audit_token_to_pid(proc.audit_token)
            let mode = ExecPolicy.auditMode ? "AUDIT" : "BLOCK"
            logger.warning("[AUTH] \(mode) OPEN: \(path) by \(name) pid=\(pid) reason=\(decision.reason)")
            let info = extractBasicProcessInfo(from: proc)
            recordSecurityEvent(.authOpen, process: info, targetPath: path,
                                detail: "policy=\(decision.reason)")
        }
    }

    /// Extract minimal process info without exec arguments (faster for high-volume events)
    func extractBasicProcessInfo(from process: es_process_t) -> ESProcessInfo {
        let pid = audit_token_to_pid(process.audit_token)
        let ppid = process.ppid
        let rpid = audit_token_to_pid(process.responsible_audit_token)
        let responsiblePid = (rpid > 0 && rpid != pid) ? rpid : 0
        let path = esStringToSwift(process.executable.pointee.path)
        let name = URL(fileURLWithPath: path).lastPathComponent

        return ESProcessInfo(
            pid: pid, ppid: ppid, responsiblePid: responsiblePid,
            path: path, name: name, arguments: [],
            userId: audit_token_to_euid(process.audit_token),
            groupId: audit_token_to_egid(process.audit_token),
            codeSigningInfo: extractCodeSigningInfo(from: process),
            timestamp: Date()
        )
    }
}
