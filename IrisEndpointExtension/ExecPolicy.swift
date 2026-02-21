import Foundation
import EndpointSecurity
import os.log

/// Fast exec policy engine for AUTH_EXEC decisions.
/// Runs in the extension process — no XPC, no network, no disk I/O in the hot path.
/// Starts in AUDIT mode: logs decisions but always allows.
enum ExecPolicy {

    /// When true, log deny decisions but allow anyway. When false, actually block.
    /// Persisted to UserDefaults so mode survives extension restart.
    /// Thread-safe: protected by modeLock (accessed from AUTH thread + XPC thread).
    private static let modeKey = "ExecPolicyAuditMode"
    private static let modeLock = NSLock()
    private static var _auditMode: Bool = {
        let defaults = UserDefaults.standard
        guard defaults.object(forKey: modeKey) != nil else { return true }
        return defaults.bool(forKey: modeKey)
    }()
    static var auditMode: Bool {
        get { modeLock.lock(); defer { modeLock.unlock() }; return _auditMode }
        set {
            modeLock.lock()
            _auditMode = newValue
            modeLock.unlock()
            UserDefaults.standard.set(newValue, forKey: modeKey)
        }
    }

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

        // Threat intel: snapshot blocklists under lock, then check
        let blocks = blockedSnapshot
        if blocks.paths.contains(path) {
            logger.warning("[POLICY] DENY: threat intel blocked path: \(path)")
            return Decision(allow: false, reason: "threat_intel_path", cache: true)
        }
        if let tid = teamId, blocks.teams.contains(tid) {
            logger.warning("[POLICY] DENY: threat intel blocked team: \(tid) path=\(path)")
            return Decision(allow: false, reason: "threat_intel_team", cache: true)
        }
        if let sid = signingId, blocks.sigs.contains(sid) {
            logger.warning("[POLICY] DENY: blocked signing ID: \(sid) path=\(path)")
            return Decision(allow: false, reason: "blocked_signing_id", cache: true)
        }

        // Default: allow
        return Decision(allow: true, reason: "default_allow", cache: true)
    }

    // MARK: - MPROTECT W→X Policy

    /// Processes allowed to make W→X memory transitions (legitimate JIT engines)
    private static let jitAllowlist: Set<String> = [
        "JavaScriptCore", "WebContent", "Safari", "Google Chrome Helper",
        "Firefox", "node", "deno", "bun", "qemu-system-aarch64",
        "qemu-system-x86_64", "Brave Browser Helper", "Microsoft Edge Helper",
    ]

    /// Evaluate a MPROTECT call adding EXECUTE permission.
    static func evaluateMprotect(
        path: String, protection: Int32, isPlatform: Bool
    ) -> Decision {
        // Fast path: not adding EXECUTE → always allow
        guard protection & 0x04 != 0 else {
            return Decision(allow: true, reason: "no_execute", cache: true)
        }

        // Platform binaries: always allow (system JIT)
        if isPlatform { return Decision(allow: true, reason: "platform_binary", cache: true) }

        // System paths: always allow
        if path.hasPrefix("/System/") || path.hasPrefix("/usr/lib/") {
            return Decision(allow: true, reason: "system_path", cache: true)
        }

        // JIT allowlist: known engines that need W→X
        let name = (path as NSString).lastPathComponent
        if jitAllowlist.contains(name) {
            return Decision(allow: true, reason: "jit_allowlist", cache: true)
        }

        // Non-system, non-JIT process requesting W→X → suspicious
        logger.warning("[POLICY] DENY MPROTECT W→X: \(path)")
        return Decision(allow: false, reason: "deny_wx", cache: false)
    }

    // MARK: - AUTH_OPEN Policy

    /// Credential file patterns that trigger AUTH_OPEN deny checks.
    /// Exact filenames use O(1) Set lookup. Variable names (SSH/GPG keys) checked via
    /// filename prefix + path suffix in evaluateOpen — avoids O(n) substring scans.
    private static let credentialFilenames: Set<String> = [
        "login.keychain-db", "keychain-2.db",
        "Login Data", "Cookies", "Web Data", "key4.db", "logins.json",
        "TCC.db",
        "exodus.wallet",  // Crypto wallet (was .contains path scan)
        "credentials",    // AWS credentials (was .contains path scan)
    ]

    /// Processes allowed to open credential files (browsers, system daemons)
    private static let credentialAllowlist: Set<String> = [
        "Safari", "Google Chrome", "Firefox", "Brave Browser",
        "Microsoft Edge", "Opera", "Vivaldi", "Arc",
        "securityd", "security", "keychainaccess", "tccd", "tccutil",
        "Dropbox", "1Password", "Bitwarden",
    ]

    /// Known locations for credential-accessing binaries.
    /// Process name alone is spoofable — verify the binary lives in a trusted location.
    private static let trustedAppPrefixes: [String] = [
        "/Applications/",
        "/System/Applications/",
        "/usr/bin/", "/usr/sbin/", "/usr/libexec/",
        "/Library/Application Support/",
    ]

    /// Evaluate an OPEN of a credential-sensitive file.
    static func evaluateOpen(
        path: String, processName: String, processPath: String,
        isPlatform: Bool, isApple: Bool
    ) -> Decision {
        // Platform binaries: always allow
        if isPlatform { return Decision(allow: true, reason: "platform_binary", cache: true) }

        // Apple system: always allow
        if isApple { return Decision(allow: true, reason: "apple_system", cache: true) }

        // Check if this is a credential file
        let filename = (path as NSString).lastPathComponent
        var isCredential = credentialFilenames.contains(filename)
        // Variable-name credentials: check filename prefix, verify parent dir via O(k) hasSuffix.
        // Only runs when Set lookup misses — avoids O(n) substring scan on every AUTH_OPEN.
        if !isCredential && filename.hasPrefix("id_") {
            isCredential = path.hasSuffix("/.ssh/" + filename)
        }
        if !isCredential && filename.hasPrefix("private-") {
            isCredential = path.hasSuffix("/.gnupg/" + filename)
        }

        guard isCredential else {
            return Decision(allow: true, reason: "non_credential", cache: true)
        }

        // Credential file + allowed process name + trusted path → allow.
        // Name-only matching is spoofable: a malicious binary named "Safari"
        // in /tmp/ would bypass. Require the binary to live in a known location.
        if credentialAllowlist.contains(processName) {
            let inTrustedLocation = trustedAppPrefixes.contains { processPath.hasPrefix($0) }
            if inTrustedLocation {
                return Decision(allow: true, reason: "credential_allowlist", cache: false)
            }
            logger.warning("[POLICY] Credential allowlist name match but untrusted path: \(processPath)")
        }

        // Credential file + unknown/untrusted process → deny
        logger.warning("[POLICY] DENY OPEN credential: \(path) by \(processName) (\(processPath))")
        return Decision(allow: false, reason: "credential_theft", cache: false)
    }

    // MARK: - Threat Intel Blocklists (updatable via XPC)

    /// Immutable blocklist snapshot — created once on update, read as a single pointer.
    /// Eliminates O(n) Set copies on every AUTH_EXEC evaluation.
    private final class Blocklist: @unchecked Sendable {
        let paths: Set<String>
        let teams: Set<String>
        let sigs: Set<String>
        init(paths: Set<String> = [], teams: Set<String> = [], sigs: Set<String> = []) {
            self.paths = paths; self.teams = teams; self.sigs = sigs
        }
    }

    private static let blocksLock = NSLock()
    private static var _blocklist = Blocklist()

    /// Thread-safe read — returns shared immutable reference (no Set copy).
    private static var blockedSnapshot: Blocklist {
        blocksLock.lock()
        defer { blocksLock.unlock() }
        return _blocklist
    }

    /// Swap blocklists atomically from main app via XPC (called on XPC thread).
    static func updateBlocklists(
        paths: Set<String>, teamIds: Set<String>, signingIds: Set<String>
    ) {
        let snapshot = Blocklist(paths: paths, teams: teamIds, sigs: signingIds)
        blocksLock.lock()
        defer { blocksLock.unlock() }
        _blocklist = snapshot
        logger.info("[POLICY] Updated blocklists: \(paths.count) paths, \(teamIds.count) teams, \(signingIds.count) sigIDs")
    }
}
