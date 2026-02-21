import Foundation
import EndpointSecurity
import os.log

/// Smart muting and path filtering for high-volume file events.
/// OPEN/WRITE events are extremely noisy — we filter to only
/// security-relevant paths (credentials, TCC, persistence, staging).
extension ESClient {

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
    /// Inline prefix checks ordered by frequency — eliminates loop overhead.
    func shouldTrackFilePath(_ path: String) -> Bool {
        let filename = (path as NSString).lastPathComponent
        if Self.watchedFilenames.contains(filename) { return true }

        // Muted system noise — ordered by event frequency
        if path.hasPrefix("/private/var/folders/") || path.hasPrefix("/private/var/db/") { return false }
        if path.hasPrefix("/System/") { return false }
        if path.hasPrefix("/Library/Caches/") { return false }
        if path.hasPrefix("/usr/lib/") || path.hasPrefix("/usr/libexec/") || path.hasPrefix("/usr/share/") { return false }
        if path.hasPrefix("/dev/") { return false }

        // Watched security-relevant paths
        if path.hasPrefix("/Users/") { return true }
        if path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") || path.hasPrefix("/var/tmp/") { return true }
        if path.hasPrefix("/Library/LaunchDaemons/") || path.hasPrefix("/Library/LaunchAgents/") { return true }
        if path.hasPrefix("/Library/Application Support/com.apple.TCC/") { return true }

        return false
    }

    // NOTE: Blanket muteNoisyFileEventPaths() removed — replaced by MuteSet
    // which applies per-event-type muting via es_mute_path_events().
    // This gives finer control: e.g. OPEN muted from /System/ but EXEC still visible.
}
