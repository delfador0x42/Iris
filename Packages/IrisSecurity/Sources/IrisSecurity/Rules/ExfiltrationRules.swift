import Foundation

/// Rules for data exfiltration: file staging, archive creation,
/// volume mounting by non-system process.
public enum ExfiltrationRules {

    public static func rules() -> [DetectionRule] {
        [
            // File written to /tmp by non-system process (staging)
            DetectionRule(
                id: "exfil_tmp_staging",
                name: "Suspicious file staging in /tmp",
                eventType: "file_write",
                conditions: [
                    .fieldMatchesRegex("target_path",
                        "^/(tmp|private/tmp|var/tmp)/.*\\.(zip|tar|gz|enc|dat)$"),
                    .processNotAppleSigned,
                ],
                severity: .medium,
                mitreId: "T1074.001",
                mitreName: "Data Staged: Local Data Staging"
            ),
            // External volume mount (USB attack vector)
            DetectionRule(
                id: "exfil_external_mount",
                name: "External volume mounted",
                eventType: "mount",
                conditions: [
                    .fieldHasPrefix("target_path", "/Volumes/"),
                ],
                severity: .low,
                mitreId: "T1025",
                mitreName: "Data from Removable Media"
            ),
            // AWS credential file access (NotLockBit exfil)
            DetectionRule(
                id: "exfil_aws_creds",
                name: "AWS credential file accessed",
                eventType: "file_open",
                conditions: [
                    .fieldContains("target_path", ".aws/credentials"),
                    .processNotAppleSigned,
                    .processNameNotIn(["aws", "aws-cli"]),
                ],
                severity: .high,
                mitreId: "T1552.001",
                mitreName: "Credentials in Files"
            ),
        ]
    }
}
