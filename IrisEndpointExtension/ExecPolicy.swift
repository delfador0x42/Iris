import Foundation
import EndpointSecurity
import os.log

/// Fast exec policy engine for AUTH_EXEC decisions.
/// Runs in the extension process — no XPC, no network, no disk I/O in the hot path.
/// Starts in AUDIT mode: logs decisions but always allows.
enum ExecPolicy {

    /// When true, log deny decisions but allow anyway. When false, actually block.
    static var auditMode = true

    struct Decision {
        let allow: Bool
        let reason: String
        let cache: Bool  // Whether ES should cache this result
    }

    private static let logger = Logger(subsystem: "com.wudan.iris.endpoint", category: "ExecPolicy")

    /// Evaluate an exec target. Must be fast (< 1ms for allow, < 10ms for deny checks).
    static func evaluate(
        path: String, pid: pid_t,
        signingId: String?, teamId: String?,
        flags: UInt32, isPlatform: Bool, isApple: Bool
    ) -> Decision {

        // Fast path: platform binaries are always allowed and cached
        if isPlatform {
            return Decision(allow: true, reason: "platform_binary", cache: true)
        }

        // Fast path: Apple-signed system binaries
        if isApple && (path.hasPrefix("/System/") || path.hasPrefix("/usr/")) {
            return Decision(allow: true, reason: "apple_system", cache: true)
        }

        // Unsigned binary from temp/download locations — suspicious
        // CS_VALID = 0x1 (kern/cs_blobs.h — not importable in userspace Swift)
        let unsigned = (flags & 0x1) == 0
        let suspiciousLocation = path.hasPrefix("/tmp/") || path.hasPrefix("/var/tmp/") ||
            path.hasPrefix("/private/tmp/") || path.hasPrefix("/private/var/tmp/") ||
            path.contains("/Downloads/") || path.contains("/.Trash/")

        if unsigned && suspiciousLocation {
            logger.warning("[POLICY] DENY: unsigned binary in suspicious location: \(path)")
            return Decision(allow: false, reason: "unsigned_suspicious_path", cache: false)
        }

        // Unsigned binary outside /Applications — flag but allow (lower confidence)
        if unsigned && !path.hasPrefix("/Applications/") && !path.hasPrefix("/System/") &&
           !path.hasPrefix("/usr/") && !path.hasPrefix("/Library/") {
            logger.info("[POLICY] FLAG: unsigned binary in unusual location: \(path)")
            return Decision(allow: true, reason: "unsigned_unusual_path", cache: false)
        }

        // Known-bad signing IDs (add real signatures as discovered)
        if let sid = signingId, blockedSigningIds.contains(sid) {
            logger.warning("[POLICY] DENY: blocked signing ID: \(sid) path=\(path)")
            return Decision(allow: false, reason: "blocked_signing_id", cache: true)
        }

        // Default: allow
        return Decision(allow: true, reason: "default_allow", cache: true)
    }

    /// Signing IDs of known-malicious tools. Extend as threat intel arrives.
    private static let blockedSigningIds: Set<String> = [
        // Placeholder — populate from threat intel feeds
    ]
}
