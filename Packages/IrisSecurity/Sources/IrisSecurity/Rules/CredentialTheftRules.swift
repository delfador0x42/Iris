import Foundation

/// Credential theft detection — zero trust, no allowlists.
/// Detects ATTACK TECHNIQUES, not "unauthorized processes."
/// Every file access is recorded by EventStream. These rules fire
/// only on high-confidence theft patterns from real malware families:
/// Banshee (python), AtomicStealer (osascript), Proton (bash),
/// CookieMiner (python), BeaverTail (node), Mac.c (ruby), Cuckoo (osascript).
public enum CredentialTheftRules {

    /// Script interpreters used by credential stealers.
    /// NOT an allowlist — these ARE the attack tools.
    static let scriptInterpreters = [
        "python3", "python", "ruby", "perl", "node",
        "osascript", "bash", "sh", "zsh", "dash", "ksh",
        "php", "lua",
    ]

    /// Tools used to extract data from credential stores
    static let extractionTools = [
        "sqlite3", "strings", "xxd", "hexdump",
    ]

    /// Combined attack tool list
    static let attackTools = scriptInterpreters + extractionTools

    public static func rules() -> [DetectionRule] {
        [
            // === KEYCHAIN THEFT ===

            // Script interpreter opening keychain files
            // Catches: Banshee (python), AtomicStealer (osascript), Proton (bash)
            DetectionRule(
                id: "cred_keychain_interpreter",
                name: "Script interpreter accessing keychain",
                eventType: "file_open",
                conditions: [
                    .fieldContains("target_path", "keychain"),
                    .processNameIn(attackTools),
                ],
                severity: .critical,
                mitreId: "T1555.001",
                mitreName: "Keychain"
            ),

            // === BROWSER CREDENTIAL THEFT ===

            // Chrome credentials accessed by attack tool
            DetectionRule(
                id: "cred_chrome_theft",
                name: "Attack tool accessing Chrome credentials",
                eventType: "file_open",
                conditions: [
                    .fieldContains("target_path", "/Google/Chrome/"),
                    .fieldMatchesRegex("target_path",
                        "(Login Data|Cookies|Web Data|History)"),
                    .processNameIn(attackTools),
                ],
                severity: .critical,
                mitreId: "T1555.003",
                mitreName: "Credentials from Web Browsers"
            ),

            // Firefox credentials accessed by attack tool
            DetectionRule(
                id: "cred_firefox_theft",
                name: "Attack tool accessing Firefox credentials",
                eventType: "file_open",
                conditions: [
                    .fieldContains("target_path", "/Firefox/Profiles/"),
                    .fieldMatchesRegex("target_path",
                        "(logins\\.json|cookies\\.sqlite|key[34]\\.db)"),
                    .processNameIn(attackTools),
                ],
                severity: .critical,
                mitreId: "T1555.003",
                mitreName: "Credentials from Web Browsers"
            ),

            // Safari credentials accessed by attack tool
            DetectionRule(
                id: "cred_safari_theft",
                name: "Attack tool accessing Safari data",
                eventType: "file_open",
                conditions: [
                    .fieldContains("target_path", "/Safari/"),
                    .fieldMatchesRegex("target_path",
                        "(Cookies\\.binarycookies|LastSession\\.plist|History\\.db)"),
                    .processNameIn(attackTools),
                ],
                severity: .critical,
                mitreId: "T1555.003",
                mitreName: "Credentials from Web Browsers"
            ),

            // Chromium-based browsers (Brave, Edge, Opera, Vivaldi)
            DetectionRule(
                id: "cred_chromium_theft",
                name: "Attack tool accessing Chromium browser credentials",
                eventType: "file_open",
                conditions: [
                    .fieldMatchesRegex("target_path",
                        "/(BraveSoftware|Microsoft Edge|com\\.operasoftware|Vivaldi)/"),
                    .fieldMatchesRegex("target_path",
                        "(Login Data|Cookies|Web Data)"),
                    .processNameIn(attackTools),
                ],
                severity: .critical,
                mitreId: "T1555.003",
                mitreName: "Credentials from Web Browsers"
            ),

            // === CRYPTO WALLET THEFT ===

            DetectionRule(
                id: "cred_crypto_wallet",
                name: "Attack tool accessing cryptocurrency wallet",
                eventType: "file_open",
                conditions: [
                    .fieldMatchesRegex("target_path",
                        "/(Exodus|Electrum|Coinomi|Atomic|Ledger Live|WalletWasabi)/"),
                    .processNameIn(attackTools),
                ],
                severity: .critical,
                mitreId: "T1005",
                mitreName: "Data from Local System"
            ),

            // === SSH KEY THEFT ===

            DetectionRule(
                id: "cred_ssh_key_theft",
                name: "Attack tool reading SSH private key",
                eventType: "file_open",
                conditions: [
                    .fieldContains("target_path", "/.ssh/id_"),
                    .processNameIn(attackTools),
                ],
                severity: .critical,
                mitreId: "T1552.004",
                mitreName: "Private Keys"
            ),

            // === STAGING DIRECTORY ACCESS ===
            // Process executing from /tmp or /var/tmp touching credential files.
            // Dropper pattern: malware extracts binary to staging dir, runs it.

            DetectionRule(
                id: "cred_staging_tmp",
                name: "Staging process (/tmp) accessing credentials",
                eventType: "file_open",
                conditions: [
                    .fieldMatchesRegex("target_path",
                        "(keychain|Login Data|Cookies|logins\\.json|\\.ssh/id_)"),
                    .processPathHasPrefix("/tmp/"),
                ],
                severity: .critical,
                mitreId: "T1555",
                mitreName: "Credentials from Password Stores"
            ),

            DetectionRule(
                id: "cred_staging_vartmp",
                name: "Staging process (/var/tmp) accessing credentials",
                eventType: "file_open",
                conditions: [
                    .fieldMatchesRegex("target_path",
                        "(keychain|Login Data|Cookies|logins\\.json|\\.ssh/id_)"),
                    .processPathHasPrefix("/var/tmp/"),
                ],
                severity: .critical,
                mitreId: "T1555",
                mitreName: "Credentials from Password Stores"
            ),

            // === POLICY ENFORCEMENT ===

            // AUTH_OPEN denied: ES blocked a credential file access.
            // Always critical — ExecPolicy actively prevented theft.
            DetectionRule(
                id: "cred_auth_open_denied",
                name: "Credential file access blocked by policy",
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
