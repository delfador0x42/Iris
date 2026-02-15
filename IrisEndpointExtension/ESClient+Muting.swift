import Foundation
import EndpointSecurity
import os.log

/// Smart muting and path filtering for high-volume file events.
/// OPEN/WRITE events are extremely noisy — we filter to only
/// security-relevant paths (credentials, TCC, persistence, staging).
extension ESClient {

    /// Paths we ALWAYS want to see file events for (security-critical)
    static let watchedPathPrefixes: [String] = [
        // Credential files
        "/Users/", // Covers keychain, browser data, wallets, SSH keys
        // TCC database (privacy bypass)
        "/Library/Application Support/com.apple.TCC/",
        // Persistence locations
        "/Library/LaunchDaemons/",
        "/Library/LaunchAgents/",
        // Staging directories
        "/tmp/", "/private/tmp/", "/var/tmp/",
    ]

    /// Paths we always SKIP (system noise, never malware-relevant)
    static let mutedPathPrefixes: [String] = [
        "/System/",
        "/usr/lib/",
        "/usr/libexec/",
        "/usr/share/",
        "/private/var/db/dyld/",
        "/private/var/db/uuidtext/",
        "/private/var/folders/",
        "/Library/Caches/",
        "/dev/",
    ]

    /// Specific filenames always worth tracking regardless of path
    static let watchedFilenames: Set<String> = [
        "TCC.db", "TCC.db-journal", "TCC.db-wal",
        "login.keychain-db", "keychain-2.db",
        "Cookies", "Login Data", "Web Data", "key4.db", "logins.json",
        ".zshenv", ".zshrc", ".bash_profile", ".bashrc",
        "authorization", "sudoers",
    ]

    /// Determine if a file path is security-relevant (worth recording).
    /// Returns false for system noise, true for credential/persistence/staging paths.
    func shouldTrackFilePath(_ path: String) -> Bool {
        let filename = (path as NSString).lastPathComponent

        // Always track known sensitive filenames
        if Self.watchedFilenames.contains(filename) { return true }

        // Skip known system noise paths
        for prefix in Self.mutedPathPrefixes {
            if path.hasPrefix(prefix) { return false }
        }

        // Track if under a watched prefix
        for prefix in Self.watchedPathPrefixes {
            if path.hasPrefix(prefix) { return true }
        }

        return false
    }

    /// Mute high-volume file event paths at the ES level.
    /// Uses target-prefix muting so file events from /System, /usr/lib, etc.
    /// never reach userspace. Process lifecycle events (EXEC/FORK/EXIT) still flow.
    func muteNoisyFileEventPaths(_ client: OpaquePointer) {
        for path in Self.mutedPathPrefixes {
            let result = es_mute_path(client, path, ES_MUTE_PATH_TYPE_TARGET_PREFIX)
            if result != ES_RETURN_SUCCESS {
                logger.warning("[ES] Failed to mute target prefix: \(path)")
            }
        }
        logger.info("[ES] Muted \(Self.mutedPathPrefixes.count) target path prefixes for file events")
    }
}
