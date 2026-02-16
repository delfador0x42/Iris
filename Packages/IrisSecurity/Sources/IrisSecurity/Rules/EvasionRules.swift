import Foundation

/// Rules from Banshee, BirdMiner, ZuRu, XCSSET, Bundlore.
/// Detects quarantine bypass, TCC manipulation, anti-analysis.
public enum EvasionRules {

    public static func rules() -> [DetectionRule] {
        [
            // Quarantine xattr removal (XCSSET, ZuRu, Bundlore)
            DetectionRule(
                id: "evasion_quarantine_bypass",
                name: "Quarantine attribute manipulation",
                eventType: "file_setextattr",
                conditions: [
                    .fieldContains("detail", "com.apple.quarantine"),
                    .processNotAppleSigned,
                ],
                severity: .high,
                mitreId: "T1553.001",
                mitreName: "Subvert Trust Controls: Gatekeeper Bypass"
            ),
            // TCC.db direct modification (Xagent, ColdRoot)
            DetectionRule(
                id: "evasion_tcc_direct_modify",
                name: "Direct TCC.db modification",
                eventType: "file_write",
                conditions: [
                    .fieldContains("target_path", "TCC.db"),
                    .processNameNotIn(["tccd", "tccutil"]),
                ],
                severity: .critical,
                mitreId: "T1548",
                mitreName: "Abuse Elevation Control Mechanism"
            ),
            // ES TCC_MODIFY event by non-system process
            DetectionRule(
                id: "evasion_tcc_modify_event",
                name: "TCC permission modified",
                eventType: "tcc_modify",
                conditions: [
                    .processNotAppleSigned,
                ],
                severity: .high,
                mitreId: "T1548",
                mitreName: "Abuse Elevation Control Mechanism"
            ),
            // setuid to root by non-system process
            DetectionRule(
                id: "evasion_setuid_root",
                name: "Process escalated to root via setuid",
                eventType: "setuid",
                conditions: [
                    .fieldEquals("detail", "uid=0"),
                    .processNotAppleSigned,
                ],
                severity: .critical,
                mitreId: "T1548.001",
                mitreName: "Setuid and Setgid"
            ),
            // Log file deletion (evidence destruction)
            DetectionRule(
                id: "evasion_log_deletion",
                name: "System log file deleted",
                eventType: "file_unlink",
                conditions: [
                    .fieldMatchesRegex("target_path", "/(var/log|Library/Logs)/"),
                    .processNotAppleSigned,
                ],
                severity: .high,
                mitreId: "T1070.002",
                mitreName: "Indicator Removal: Clear Linux or Mac System Logs"
            ),
            // setgid to wheel/admin by non-system process (privilege escalation)
            DetectionRule(
                id: "evasion_setgid_escalation",
                name: "Process changed group via setgid",
                eventType: "setgid",
                conditions: [
                    .processNotAppleSigned,
                ],
                severity: .high,
                mitreId: "T1548.001",
                mitreName: "Setuid and Setgid"
            ),
            // sudo usage by non-interactive process (automated privilege escalation)
            DetectionRule(
                id: "evasion_sudo_abuse",
                name: "sudo invoked by non-system process",
                eventType: "sudo",
                conditions: [
                    .processNotAppleSigned,
                ],
                severity: .high,
                mitreId: "T1548.003",
                mitreName: "Sudo and Sudo Caching"
            ),
            // Process suspend/resume by non-system process (anti-forensics: freeze defenders)
            DetectionRule(
                id: "evasion_proc_suspend",
                name: "Process suspended by non-system binary",
                eventType: "proc_suspend_resume",
                conditions: [
                    .processNotAppleSigned,
                ],
                severity: .high,
                mitreId: "T1562.001",
                mitreName: "Impair Defenses: Disable or Modify Tools"
            ),
            // Suspicious process genealogy: browser/office → shell
            // (Dropper pattern: app exploited → spawns shell → payload)
            DetectionRule(
                id: "evasion_browser_shell_spawn",
                name: "Browser/office app spawned shell process",
                eventType: "auth_exec",
                conditions: [
                    .processNameIn(["sh", "bash", "zsh", "dash", "ksh"]),
                    .parentNameIn(["Safari", "Google Chrome", "Firefox",
                                   "Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint",
                                   "Pages", "Numbers", "Keynote", "Preview",
                                   "Mail", "Messages"]),
                ],
                severity: .critical,
                mitreId: "T1059.004",
                mitreName: "Command and Scripting Interpreter: Unix Shell"
            ),
        ]
    }
}
