import Foundation
import EndpointSecurity
import os.log

/// AUTH_EXEC handler: evaluates exec policy and responds with allow/deny.
/// In audit mode, always allows but logs what would have been blocked.
extension ESClient {

    func handleAuthExec(_ message: UnsafePointer<es_message_t>) {
        let target = message.pointee.event.exec.target.pointee
        let path = esStringToSwift(target.executable.pointee.path)
        let pid = audit_token_to_pid(target.audit_token)
        let signingId = esStringToSwift(target.signing_id)
        let teamId = esStringToSwift(target.team_id)
        let flags = target.codesigning_flags
        let isPlatform = target.is_platform_binary

        let isApple = isPlatform || (signingId.hasPrefix("com.apple.") && teamId.isEmpty)

        let decision = ExecPolicy.evaluate(
            path: path, pid: pid,
            signingId: signingId.isEmpty ? nil : signingId,
            teamId: teamId.isEmpty ? nil : teamId,
            flags: flags, isPlatform: isPlatform, isApple: isApple
        )

        // In audit mode: always allow, but log denies
        let effectiveAllow = ExecPolicy.auditMode ? true : decision.allow

        let result: es_auth_result_t = effectiveAllow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
        let cache = decision.allow ? decision.cache : false  // Never cache denies in audit mode

        guard let client = self.client else { return }
        let respondResult = es_respond_auth_result(client, message, result, cache)

        if respondResult != ES_RESPOND_RESULT_SUCCESS {
            logger.error("[AUTH] Failed to respond to AUTH_EXEC for PID \(pid): \(respondResult.rawValue)")
        }

        // Log non-trivial decisions
        if !decision.allow {
            let mode = ExecPolicy.auditMode ? "AUDIT" : "BLOCK"
            logger.warning("[AUTH] \(mode) EXEC: \(path) reason=\(decision.reason) pid=\(pid)")
        }

        // Record as security event for the main app's DetectionEngine.
        // Skip platform binaries (too noisy) — only log interesting decisions.
        if !decision.allow || decision.reason != "platform_binary" {
            let info = extractBasicProcessInfo(from: target)
            recordSecurityEvent(.authExec, process: info, targetPath: path,
                                detail: "policy=\(decision.reason) allow=\(effectiveAllow)")
        }

        // NOTE: Don't update processTable or execCount here.
        // AUTH_EXEC fires before exec; NOTIFY_EXEC fires after and handles table updates.
        // Both fire for allowed execs — updating here would double-count.
    }
}
