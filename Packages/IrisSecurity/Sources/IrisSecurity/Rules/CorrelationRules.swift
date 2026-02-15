import Foundation

/// Multi-stage correlation rules derived from real malware kill chains.
/// Each rule requires multiple events from the same process within a time window.
public enum CorrelationRuleDefinitions {

    public static func rules() -> [CorrelationRule] {
        [
            // Credential theft chain: open credential file → network connection
            // (AtomicStealer, Banshee, BeaverTail pattern)
            CorrelationRule(
                id: "corr_cred_theft_exfil",
                name: "Credential access followed by network connection",
                stages: [
                    RuleStage(
                        eventType: "file_open",
                        conditions: [
                            .fieldMatchesRegex("target_path",
                                "(keychain|Login Data|Cookies|logins\\.json|key4\\.db)"),
                        ]
                    ),
                    RuleStage(eventType: "connection"),
                ],
                timeWindow: 30,
                correlationKey: .processPath,
                severity: .critical,
                mitreId: "T1555",
                mitreName: "Credential theft + exfiltration chain"
            ),

            // Staged exfiltration: write to /tmp → open same → network
            // (CloudMensis, Calisto pattern)
            CorrelationRule(
                id: "corr_staged_exfil",
                name: "Staged data exfiltration via /tmp",
                stages: [
                    RuleStage(
                        eventType: "file_write",
                        conditions: [.fieldHasPrefix("target_path", "/tmp/")]
                    ),
                    RuleStage(eventType: "connection"),
                ],
                timeWindow: 60,
                correlationKey: .processPath,
                severity: .high,
                mitreId: "T1074.001",
                mitreName: "Staged exfiltration"
            ),

            // Fake password prompt chain: osascript → write → network
            // (AtomicStealer, Banshee, MacStealer pattern)
            CorrelationRule(
                id: "corr_fake_prompt",
                name: "Fake password prompt + exfiltration",
                stages: [
                    RuleStage(
                        eventType: "exec",
                        conditions: [.fieldContains("process_name", "osascript")]
                    ),
                    RuleStage(eventType: "file_write"),
                    RuleStage(eventType: "connection"),
                ],
                timeWindow: 30,
                correlationKey: .pid,
                severity: .critical,
                mitreId: "T1056.002",
                mitreName: "Fake password prompt chain"
            ),

            // Persistence + execution: write LaunchAgent → exec payload
            // (Generic persistence-then-run pattern)
            CorrelationRule(
                id: "corr_persist_exec",
                name: "Persistence installation + payload execution",
                stages: [
                    RuleStage(
                        eventType: "file_write",
                        conditions: [.fieldContains("target_path", "LaunchAgents/")]
                    ),
                    RuleStage(eventType: "exec"),
                ],
                timeWindow: 120,
                correlationKey: .processPath,
                severity: .high,
                mitreId: "T1543.001",
                mitreName: "Persistence + execution chain"
            ),
        ]
    }
}
