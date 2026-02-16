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

            // Memory injection + C2: mmap executable → mprotect W→X → network
            // (Active implant pattern: dylib load + shellcode + phone home)
            CorrelationRule(
                id: "corr_injection_c2",
                name: "Memory injection + C2 activation",
                stages: [
                    RuleStage(eventType: "mmap", conditions: [.processNotAppleSigned]),
                    RuleStage(eventType: "mprotect", conditions: [.processNotAppleSigned]),
                    RuleStage(eventType: "connection"),
                ],
                timeWindow: 120,
                correlationKey: .processPath,
                severity: .critical,
                mitreId: "T1055",
                mitreName: "Process injection + C2"
            ),

            // Thread injection + credential theft
            // (Inject into trusted process, then steal credentials)
            CorrelationRule(
                id: "corr_thread_inject_cred",
                name: "Thread injection + credential theft",
                stages: [
                    RuleStage(eventType: "remote_thread_create", conditions: [.processNotAppleSigned]),
                    RuleStage(
                        eventType: "file_open",
                        conditions: [
                            .fieldMatchesRegex("target_path",
                                "(keychain|Login Data|Cookies|key4\\.db|logins\\.json)")
                        ]
                    ),
                ],
                timeWindow: 60,
                correlationKey: .pid,
                severity: .critical,
                mitreId: "T1055",
                mitreName: "Injection + credential theft"
            ),

            // Thread injection + shellcode + exfiltration (Pegasus-style)
            CorrelationRule(
                id: "corr_thread_wx_exfil",
                name: "Thread injection + shellcode + exfiltration",
                stages: [
                    RuleStage(eventType: "remote_thread_create", conditions: [.processNotAppleSigned]),
                    RuleStage(eventType: "mprotect"),
                    RuleStage(eventType: "connection"),
                ],
                timeWindow: 60,
                correlationKey: .pid,
                severity: .critical,
                mitreId: "T1055",
                mitreName: "Thread injection + shellcode + C2"
            ),
        ]
    }
}
