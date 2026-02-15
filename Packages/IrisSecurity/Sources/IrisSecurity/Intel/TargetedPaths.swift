import Foundation

/// Files that macOS malware commonly targets for theft.
/// Derived from analysis of 214 malware families.
public enum TargetedPaths {

    public static func indicators() -> [ThreatIndicator] {
        paths.map { entry in
            ThreatIndicator(
                type: .filePath,
                value: entry.path,
                malwareFamily: entry.family,
                mitreId: entry.mitre,
                severity: entry.severity
            )
        }
    }

    private struct Entry {
        let path: String; let family: String
        let mitre: String; let severity: AnomalySeverity
    }

    private static let paths: [Entry] = [
        // Browser credentials (Banshee, AtomicStealer, XCSSET, Cuckoo)
        Entry(path: "Google/Chrome/Default/Login Data", family: "Stealer", mitre: "T1555.003", severity: .critical),
        Entry(path: "Google/Chrome/Default/Cookies", family: "Stealer", mitre: "T1555.003", severity: .critical),
        Entry(path: "Firefox/Profiles/", family: "Stealer", mitre: "T1555.003", severity: .critical),
        Entry(path: "BraveSoftware/Brave-Browser/Default/Login Data", family: "Stealer", mitre: "T1555.003", severity: .critical),
        Entry(path: "Microsoft Edge/Default/Login Data", family: "Stealer", mitre: "T1555.003", severity: .critical),

        // Cryptocurrency wallets (AtomicStealer, Cuckoo, BeaverTail)
        Entry(path: "Exodus/exodus.wallet", family: "Stealer", mitre: "T1005", severity: .critical),
        Entry(path: ".electrum/wallets", family: "Stealer", mitre: "T1005", severity: .critical),
        Entry(path: "Coinomi/wallets", family: "Stealer", mitre: "T1005", severity: .critical),
        Entry(path: "Atomic/Local Storage", family: "Stealer", mitre: "T1005", severity: .critical),
        Entry(path: "Ledger Live", family: "Stealer", mitre: "T1005", severity: .critical),

        // Keychains
        Entry(path: "Library/Keychains/login.keychain-db", family: "Stealer", mitre: "T1555.001", severity: .critical),

        // SSH keys (ZuRu)
        Entry(path: ".ssh/id_rsa", family: "ZuRu", mitre: "T1552.004", severity: .high),
        Entry(path: ".ssh/id_ed25519", family: "ZuRu", mitre: "T1552.004", severity: .high),

        // Cloud credentials (NotLockBit)
        Entry(path: ".aws/credentials", family: "NotLockBit", mitre: "T1552.001", severity: .high),
        Entry(path: ".azure/", family: "NotLockBit", mitre: "T1552.001", severity: .high),

        // TCC database
        Entry(path: "com.apple.TCC/TCC.db", family: "Xagent", mitre: "T1548", severity: .critical),

        // Additional browser targets
        Entry(path: "Vivaldi/Default/Login Data", family: "Stealer", mitre: "T1555.003", severity: .critical),
        Entry(path: "Opera Software/Opera Stable/Login Data", family: "Stealer", mitre: "T1555.003", severity: .critical),
        Entry(path: "Cookies/Cookies.binarycookies", family: "Stealer", mitre: "T1555.003", severity: .high),

        // Additional wallets
        Entry(path: "com.liberty.jaxx/Local Storage", family: "Stealer", mitre: "T1005", severity: .critical),
        Entry(path: "Wasabi Wallet", family: "Stealer", mitre: "T1005", severity: .critical),
        Entry(path: "Binance", family: "Stealer", mitre: "T1005", severity: .critical),
        Entry(path: "MetaMask", family: "Stealer", mitre: "T1005", severity: .critical),

        // Notes / Messages / Mail
        Entry(path: "group.com.apple.notes/NoteStore.sqlite", family: "Stealer", mitre: "T1005", severity: .high),
        Entry(path: "Library/Messages/chat.db", family: "Stealer", mitre: "T1005", severity: .high),

        // Cloud/dev credentials
        Entry(path: ".gcloud/credentials.db", family: "Stealer", mitre: "T1552.001", severity: .high),
        Entry(path: ".kube/config", family: "Stealer", mitre: "T1552.001", severity: .high),
        Entry(path: ".docker/config.json", family: "Stealer", mitre: "T1552.001", severity: .high),
        Entry(path: ".npmrc", family: "Stealer", mitre: "T1552.001", severity: .medium),

        // GPG keys
        Entry(path: ".gnupg/private-keys-v1.d", family: "Stealer", mitre: "T1552.004", severity: .high),
    ]

    /// Check if a path matches a known targeted file
    public static func isTargeted(_ path: String) -> ThreatIndicator? {
        paths.first { path.contains($0.path) }.map { entry in
            ThreatIndicator(
                type: .filePath, value: entry.path,
                malwareFamily: entry.family,
                mitreId: entry.mitre, severity: entry.severity
            )
        }
    }
}
