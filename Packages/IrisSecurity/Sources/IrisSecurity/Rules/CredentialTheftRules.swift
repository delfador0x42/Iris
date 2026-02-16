import Foundation

/// Rules from Banshee, CookieMiner, Proton, AtomicStealer, Mac.c, BeaverTail, Cuckoo.
/// Detects non-browser processes accessing credential stores.
public enum CredentialTheftRules {

    /// Known browser signing IDs that legitimately access credential files
    static let browserSigningIds = [
        "Safari", "com.apple.Safari", "com.google.Chrome",
        "org.mozilla.firefox", "com.brave.Browser",
        "com.microsoft.edgemac", "com.operasoftware.Opera",
        "com.vivaldi.Vivaldi",
    ]

    public static func rules() -> [DetectionRule] {
        [
            // Non-browser opening Chrome Login Data (Banshee, AtomicStealer, XCSSET)
            DetectionRule(
                id: "cred_chrome_login_data",
                name: "Non-browser accessing Chrome credentials",
                eventType: "file_open",
                conditions: [
                    .fieldContains("target_path", "/Google/Chrome/Default/Login Data"),
                    .processNotAppleSigned,
                    .processNameNotIn(["Google Chrome", "Chrome", "chrome"]),
                ],
                severity: .critical,
                mitreId: "T1555.003",
                mitreName: "Credentials from Web Browsers"
            ),
            // Keychain file access by non-system process
            DetectionRule(
                id: "cred_keychain_access",
                name: "Keychain file access by script interpreter",
                eventType: "file_open",
                conditions: [
                    .fieldContains("target_path", "login.keychain-db"),
                    .processNameNotIn(["securityd", "security", "keychainaccess"]),
                ],
                severity: .high,
                mitreId: "T1555.001",
                mitreName: "Keychain"
            ),
            // sqlite3 accessing browser DBs (CookieMiner technique)
            DetectionRule(
                id: "cred_sqlite3_browser_db",
                name: "sqlite3 reading browser credential database",
                eventType: "file_open",
                conditions: [
                    .fieldContains("target_path", "/Cookies"),
                    .processNameNotIn(browserSigningIds + ["sqlite3"]),
                ],
                severity: .high,
                mitreId: "T1555.003",
                mitreName: "Credentials from Web Browsers"
            ),
            // Firefox credential DB access
            DetectionRule(
                id: "cred_firefox_logins",
                name: "Non-browser accessing Firefox credentials",
                eventType: "file_open",
                conditions: [
                    .fieldContains("target_path", "/Firefox/Profiles/"),
                    .fieldContains("target_path", "logins.json"),
                    .processNameNotIn(["firefox", "Firefox"]),
                ],
                severity: .critical,
                mitreId: "T1555.003",
                mitreName: "Credentials from Web Browsers"
            ),
            // Crypto wallet file access (AtomicStealer, Cuckoo, BeaverTail)
            DetectionRule(
                id: "cred_crypto_wallet",
                name: "Process accessing cryptocurrency wallet",
                eventType: "file_open",
                conditions: [
                    .fieldMatchesRegex("target_path",
                        "/(Exodus|Electrum|Coinomi|Atomic|Ledger Live|WalletWasabi)/"),
                    .processNotAppleSigned,
                ],
                severity: .high,
                mitreId: "T1005",
                mitreName: "Data from Local System"
            ),
            // SSH key access by non-ssh process
            DetectionRule(
                id: "cred_ssh_key_access",
                name: "Non-SSH process reading SSH keys",
                eventType: "file_open",
                conditions: [
                    .fieldContains("target_path", "/.ssh/id_"),
                    .processNameNotIn(["ssh", "ssh-agent", "sshd", "ssh-keygen", "git"]),
                ],
                severity: .high,
                mitreId: "T1552.004",
                mitreName: "Private Keys"
            ),
            // AUTH_OPEN: credential file access blocked by ExecPolicy
            DetectionRule(
                id: "cred_auth_open_denied",
                name: "Credential file access blocked",
                eventType: "auth_open",
                conditions: [
                    .processNotAppleSigned,
                ],
                severity: .critical,
                mitreId: "T1555",
                mitreName: "Credentials from Password Stores"
            ),
        ]
    }
}
