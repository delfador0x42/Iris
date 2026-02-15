import Foundation

/// Rules from XCSSET, Eleanor, CloudMensis, ChillyHell, Activator, CookieMiner.
/// Detects new persistence mechanisms being installed.
public enum PersistenceRules {

    public static func rules() -> [DetectionRule] {
        [
            // BTM persistence by non-installer (XCSSET, Eleanor)
            DetectionRule(
                id: "persist_btm_non_installer",
                name: "Persistence installed via BTM",
                eventType: "btm_launch_item_add",
                conditions: [
                    .processNotAppleSigned,
                    .processNameNotIn(["Installer", "installer", "softwareupdated"]),
                ],
                severity: .high,
                mitreId: "T1543.004",
                mitreName: "Launch Agent/Daemon"
            ),
            // Write to LaunchAgents directory (CloudMensis, Activator, CookieMiner)
            DetectionRule(
                id: "persist_launch_agent_write",
                name: "File written to LaunchAgents directory",
                eventType: "file_write",
                conditions: [
                    .fieldContains("target_path", "/LaunchAgents/"),
                    .processNotAppleSigned,
                ],
                severity: .high,
                mitreId: "T1543.001",
                mitreName: "Launch Agent"
            ),
            // Write to LaunchDaemons (requires root — more suspicious)
            DetectionRule(
                id: "persist_launch_daemon_write",
                name: "File written to LaunchDaemons directory",
                eventType: "file_write",
                conditions: [
                    .fieldContains("target_path", "/LaunchDaemons/"),
                    .processNotAppleSigned,
                ],
                severity: .critical,
                mitreId: "T1543.004",
                mitreName: "Launch Daemon"
            ),
            // Shell profile modification (ChillyHell, CloudMensis)
            DetectionRule(
                id: "persist_shell_profile",
                name: "Shell profile modified",
                eventType: "file_write",
                conditions: [
                    .fieldMatchesRegex("target_path", "/\\.(zshenv|zshrc|bash_profile|bashrc)$"),
                ],
                severity: .high,
                mitreId: "T1546.004",
                mitreName: "Unix Shell Configuration Modification"
            ),
            // Xcode project injection (XCSSET, XcodeSpy)
            DetectionRule(
                id: "persist_xcode_injection",
                name: "Xcode project file modified",
                eventType: "file_write",
                conditions: [
                    .fieldContains("target_path", ".xcodeproj/"),
                    .processNameNotIn(["Xcode", "xcodebuild"]),
                ],
                severity: .critical,
                mitreId: "T1195.002",
                mitreName: "Supply Chain: Compromise Software Supply Chain"
            ),
            // Cron job creation
            DetectionRule(
                id: "persist_cron_write",
                name: "Cron job created",
                eventType: "file_write",
                conditions: [
                    .fieldHasPrefix("target_path", "/var/at/tabs/"),
                    .processNotAppleSigned,
                ],
                severity: .medium,
                mitreId: "T1053.003",
                mitreName: "Cron"
            ),
        ]
    }
}
