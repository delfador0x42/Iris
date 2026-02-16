import Foundation

/// Detection rules from 2024-2025 APT campaigns.
/// Covers: RustyAttr, FlexibleFerret, Cuckoo, NotLockBit, RustDoor, supply chain.
public enum APTRules {
    public static func rules() -> [DetectionRule] { [
        // FlexibleFerret: Dropbox API exfiltration from non-Dropbox process
        DetectionRule(
            id: "apt_dropbox_exfil", name: "Dropbox API Exfiltration",
            eventType: "connection",
            conditions: [
                .fieldContains("hostname", "content.dropboxapi.com"),
                .processNameNotIn(["Dropbox", "Dropbox Helper", "dbfseventsd"]),
            ],
            severity: .critical, mitreId: "T1567.002", mitreName: "Exfil Over Cloud Storage"),

        // FlexibleFerret/Banshee: IP lookup services from unsigned process
        DetectionRule(
            id: "apt_ip_lookup", name: "External IP Lookup",
            eventType: "connection",
            conditions: [
                .fieldContains("hostname", "api.ipify.org"),
                .processNotAppleSigned,
            ],
            severity: .high, mitreId: "T1016.001", mitreName: "Internet Connection Discovery"),

        // NotLockBit: AWS S3 exfiltration
        DetectionRule(
            id: "apt_s3_exfil", name: "AWS S3 Exfiltration",
            eventType: "connection",
            conditions: [
                .fieldContains("hostname", "s3.amazonaws.com"),
                .processNotAppleSigned,
                .processNameNotIn(["aws", "awscli", "aws-cli"]),
            ],
            severity: .critical, mitreId: "T1567.002", mitreName: "Exfil Over Cloud Storage"),

        // NotLockBit: Desktop wallpaper change via osascript (ransomware indicator)
        DetectionRule(
            id: "apt_wallpaper_change", name: "Desktop Wallpaper Change via Script",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["osascript"]),
                .fieldContains("args", "desktop picture"),
            ],
            severity: .critical, mitreId: "T1491", mitreName: "Defacement"),

        // Supply chain: npm preinstall hook spawning network connections
        DetectionRule(
            id: "apt_npm_preinstall", name: "npm Lifecycle Script Network Access",
            eventType: "auth_exec",
            conditions: [
                .fieldContains("args", "preinstall"),
                .fieldContains("parent_path", "node_modules"),
            ],
            severity: .high, mitreId: "T1195.001", mitreName: "Supply Chain Compromise"),

        // RustDoor: Cron + LaunchAgent combined persistence (double persistence)
        DetectionRule(
            id: "apt_cron_write", name: "Cron Job Creation",
            eventType: "file_write",
            conditions: [
                .fieldContains("target_path", "/var/at/tabs/"),
                .processNotAppleSigned,
            ],
            severity: .high, mitreId: "T1053.003", mitreName: "Cron"),

        // RustDoor: .zshrc modification by non-shell process
        DetectionRule(
            id: "apt_zshrc_hijack", name: "Shell Profile Modification",
            eventType: "file_write",
            conditions: [
                .fieldContains("target_path", ".zshrc"),
                .processNameNotIn(["zsh", "bash", "sh", "vim", "nvim", "nano", "code", "cursor"]),
            ],
            severity: .critical, mitreId: "T1546.004", mitreName: "Unix Shell Config Modification"),

        // CVE-2024-44243: SIP bypass via storagekitd
        DetectionRule(
            id: "apt_filesystems_write", name: "Write to /Library/Filesystems",
            eventType: "file_write",
            conditions: [
                .fieldContains("target_path", "/Library/Filesystems/"),
            ],
            severity: .critical, mitreId: "T1553.006", mitreName: "Code Signing Policy Modification"),

        // Mass file rename with single extension (ransomware)
        DetectionRule(
            id: "apt_mass_rename", name: "Mass File Rename (Ransomware)",
            eventType: "file_rename",
            conditions: [
                .fieldContains("target_path", ".abcd"),  // NotLockBit extension
            ],
            severity: .critical, mitreId: "T1486", mitreName: "Data Encrypted for Impact"),

        // Staging to /var/tmp by non-system process (FlexibleFerret)
        DetectionRule(
            id: "apt_var_tmp_staging", name: "Payload Drop in /var/tmp",
            eventType: "file_write",
            conditions: [
                .fieldHasPrefix("target_path", "/var/tmp/"),
                .processNotAppleSigned,
            ],
            severity: .high, mitreId: "T1074.001", mitreName: "Local Data Staging"),
    ] }
}
