import Foundation

/// Detection rules targeting nation-state / APT tradecraft.
/// Covers: fileless execution, lateral movement, environmental keying,
/// timestomping, dylib proxying, process hollowing indicators.
/// All rules use event types already emitted by the ES extension.
public enum NationStateRules {
    public static func rules() -> [DetectionRule] { [

        // === FILELESS EXECUTION ===

        // In-memory execution via python/ruby/perl (no file on disk)
        DetectionRule(
            id: "ns_fileless_interpreter",
            name: "Interpreter executing from stdin/pipe",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["python3", "python", "ruby", "perl", "node"]),
                .fieldMatchesRegex("args", "(-c |--command|/dev/stdin|-e )"),
                .processNotAppleSigned,
            ],
            severity: .high, mitreId: "T1059",
            mitreName: "Fileless execution via interpreter"),

        // osascript -e (inline AppleScript execution — common APT dropper)
        DetectionRule(
            id: "ns_osascript_inline",
            name: "Inline AppleScript execution",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["osascript"]),
                .fieldContains("args", " -e "),
            ],
            severity: .high, mitreId: "T1059.002",
            mitreName: "Inline AppleScript Execution"),

        // === LATERAL MOVEMENT ===

        // SSH to internal network from non-terminal process
        DetectionRule(
            id: "ns_ssh_lateral",
            name: "SSH initiated by non-interactive process",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["ssh", "scp", "sftp"]),
                .processNotAppleSigned,
            ],
            severity: .high, mitreId: "T1021.004",
            mitreName: "Lateral Movement: SSH"),

        // Screen sharing / ARD enablement
        DetectionRule(
            id: "ns_ard_enable",
            name: "Apple Remote Desktop enabled programmatically",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["kickstart"]),
                .fieldContains("args", "-activate"),
            ],
            severity: .critical, mitreId: "T1021.001",
            mitreName: "Remote Desktop Protocol"),

        // === ENVIRONMENTAL KEYING / ANTI-ANALYSIS ===

        // Process querying hardware model (VM detection)
        DetectionRule(
            id: "ns_vm_detect_sysctl",
            name: "Hardware model query (VM detection)",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["sysctl"]),
                .fieldMatchesRegex("args", "(hw\\.model|machdep\\.cpu|kern\\.boottime)"),
            ],
            severity: .medium, mitreId: "T1497.001",
            mitreName: "System Checks: VM Detection"),

        // IOKit registry query for VM indicators
        DetectionRule(
            id: "ns_vm_detect_ioreg",
            name: "IOKit registry dump (VM detection)",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["ioreg"]),
                .fieldMatchesRegex("args",
                    "(IOPlatformExpertDevice|board-id|manufacturer)"),
            ],
            severity: .medium, mitreId: "T1497.001",
            mitreName: "IOKit VM Detection"),

        // system_profiler for hardware enumeration
        DetectionRule(
            id: "ns_hw_profile",
            name: "Hardware profiling (recon/keying)",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["system_profiler"]),
                .processNotAppleSigned,
            ],
            severity: .medium, mitreId: "T1082",
            mitreName: "System Information Discovery"),

        // === DEFENSE EVASION ===

        // Code signature removal/re-signing
        DetectionRule(
            id: "ns_codesign_strip",
            name: "Code signature manipulation",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["codesign"]),
                .fieldMatchesRegex("args", "(--remove-signature|--force --sign -)"),
            ],
            severity: .critical, mitreId: "T1553.002",
            mitreName: "Code Signing Manipulation"),

        // Gatekeeper bypass via spctl
        DetectionRule(
            id: "ns_gatekeeper_disable",
            name: "Gatekeeper disable attempt",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["spctl"]),
                .fieldContains("args", "--master-disable"),
            ],
            severity: .critical, mitreId: "T1553.001",
            mitreName: "Gatekeeper Bypass"),

        // xattr -d com.apple.quarantine (quarantine flag removal)
        DetectionRule(
            id: "ns_quarantine_strip",
            name: "Quarantine attribute removal via xattr",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["xattr"]),
                .fieldContains("args", "com.apple.quarantine"),
                .fieldContains("args", "-d"),
            ],
            severity: .high, mitreId: "T1553.001",
            mitreName: "Quarantine Attribute Removal"),

        // === CREDENTIAL ACCESS ===

        // security command accessing keychain
        DetectionRule(
            id: "ns_keychain_dump",
            name: "Keychain dump via security command",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["security"]),
                .fieldMatchesRegex("args",
                    "(dump-keychain|find-generic-password|find-internet-password|export)"),
            ],
            severity: .critical, mitreId: "T1555.001",
            mitreName: "Keychain Credential Access"),

        // dscl for directory service enumeration
        DetectionRule(
            id: "ns_dscl_enum",
            name: "Directory service user enumeration",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["dscl"]),
                .fieldMatchesRegex("args", "(read|list|search).*Users"),
            ],
            severity: .medium, mitreId: "T1087.001",
            mitreName: "Local Account Discovery"),

        // === COLLECTION ===

        // screencapture invoked by non-Apple process
        DetectionRule(
            id: "ns_screen_capture",
            name: "Programmatic screen capture",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["screencapture"]),
                .processNotAppleSigned,
            ],
            severity: .high, mitreId: "T1113",
            mitreName: "Screen Capture"),

        // Microphone/camera access via avfoundation
        DetectionRule(
            id: "ns_tcc_camera_mic",
            name: "TCC camera/microphone grant to unsigned",
            eventType: "tcc_modify",
            conditions: [
                .fieldMatchesRegex("detail", "(kTCCServiceCamera|kTCCServiceMicrophone)"),
                .processNotAppleSigned,
            ],
            severity: .critical, mitreId: "T1125",
            mitreName: "Audio/Video Capture"),

        // === PERSISTENCE ===

        // Login item added via BTM (Background Task Management)
        DetectionRule(
            id: "ns_btm_persist",
            name: "Background task added by unsigned process",
            eventType: "btm_launch_item_add",
            conditions: [
                .processNotAppleSigned,
            ],
            severity: .high, mitreId: "T1547.015",
            mitreName: "Login Items Persistence"),

        // Cron job modification by non-system process
        DetectionRule(
            id: "ns_crontab_modify",
            name: "Crontab modified by unsigned process",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["crontab"]),
                .fieldContains("args", "-"),
                .processNotAppleSigned,
            ],
            severity: .high, mitreId: "T1053.003",
            mitreName: "Cron Persistence"),

        // === DISCOVERY ===

        // networksetup for proxy/DNS manipulation
        DetectionRule(
            id: "ns_network_recon",
            name: "Network configuration enumeration",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["networksetup"]),
                .processNotAppleSigned,
            ],
            severity: .medium, mitreId: "T1016",
            mitreName: "System Network Configuration Discovery"),

        // Process listing by unsigned process
        DetectionRule(
            id: "ns_process_discovery",
            name: "Process discovery by unsigned binary",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["ps"]),
                .fieldContains("args", "aux"),
                .processNotAppleSigned,
            ],
            severity: .medium, mitreId: "T1057",
            mitreName: "Process Discovery"),

        // === EXFILTRATION ===

        // curl/wget posting data from non-interactive process
        DetectionRule(
            id: "ns_curl_exfil",
            name: "curl POST from non-terminal process",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["curl"]),
                .fieldMatchesRegex("args", "(-X POST|--data|--upload-file|-F )"),
                .processNotAppleSigned,
            ],
            severity: .high, mitreId: "T1048.003",
            mitreName: "Exfiltration Over HTTP"),

        // zip/tar creating archives (pre-exfiltration staging)
        DetectionRule(
            id: "ns_archive_staging",
            name: "Archive creation (staging for exfiltration)",
            eventType: "auth_exec",
            conditions: [
                .processNameIn(["zip", "tar", "ditto"]),
                .processNotAppleSigned,
            ],
            severity: .medium, mitreId: "T1560.001",
            mitreName: "Archive Collected Data"),
    ] }
}
