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
                        eventType: "auth_exec",
                        conditions: [.processNameIn(["osascript"])]
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
                    RuleStage(eventType: "auth_exec"),
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

            // === NATION-STATE KILL CHAINS ===

            // Recon → credential theft → exfil (APT29/Cozy Bear pattern)
            // Process discovers environment, then steals creds, then phones home
            CorrelationRule(
                id: "corr_ns_recon_steal_exfil",
                name: "Recon → credential theft → exfiltration",
                stages: [
                    RuleStage(
                        eventType: "auth_exec",
                        conditions: [
                            .processNameIn(["system_profiler", "sw_vers", "sysctl",
                                            "networksetup", "ifconfig", "arp"]),
                        ]
                    ),
                    RuleStage(
                        eventType: "file_open",
                        conditions: [
                            .fieldMatchesRegex("target_path",
                                "(keychain|Login Data|Cookies|key4\\.db|ssh/id_)"),
                        ]
                    ),
                    RuleStage(eventType: "connection"),
                ],
                timeWindow: 300,
                correlationKey: .processPath,
                severity: .critical,
                mitreId: "T1082 → T1555 → T1041",
                mitreName: "APT recon → credential theft → exfiltration"
            ),

            // Lateral movement chain: SSH key theft → SSH connection
            CorrelationRule(
                id: "corr_ns_ssh_lateral",
                name: "SSH key theft + lateral movement",
                stages: [
                    RuleStage(
                        eventType: "file_open",
                        conditions: [.fieldMatchesRegex("target_path", "\\.ssh/(id_|known_hosts|config)")]
                    ),
                    RuleStage(
                        eventType: "auth_exec",
                        conditions: [.processNameIn(["ssh", "scp", "sftp"])]
                    ),
                ],
                timeWindow: 120,
                correlationKey: .processPath,
                severity: .critical,
                mitreId: "T1552.004 → T1021.004",
                mitreName: "SSH key theft + lateral movement"
            ),

            // Persistence install → code sign strip → execution (evasion chain)
            CorrelationRule(
                id: "corr_ns_persist_evade_exec",
                name: "Persistence + signature strip + execution",
                stages: [
                    RuleStage(
                        eventType: "file_write",
                        conditions: [
                            .fieldMatchesRegex("target_path",
                                "(LaunchAgents|LaunchDaemons|StartupItems)/"),
                        ]
                    ),
                    RuleStage(
                        eventType: "auth_exec",
                        conditions: [.processNameIn(["codesign", "xattr"])]
                    ),
                    RuleStage(
                        eventType: "auth_exec",
                        conditions: [.processNotAppleSigned]
                    ),
                ],
                timeWindow: 180,
                correlationKey: .processPath,
                severity: .critical,
                mitreId: "T1543 → T1553 → T1204",
                mitreName: "Persistence + evasion + execution chain"
            ),

            // Data collection → archive → exfil (exfiltration chain)
            CorrelationRule(
                id: "corr_ns_collect_archive_exfil",
                name: "Data collection → archive → exfiltration",
                stages: [
                    RuleStage(
                        eventType: "file_open",
                        conditions: [
                            .fieldMatchesRegex("target_path",
                                "(Documents|Desktop|Downloads)/"),
                        ]
                    ),
                    RuleStage(
                        eventType: "auth_exec",
                        conditions: [.processNameIn(["zip", "tar", "ditto"])]
                    ),
                    RuleStage(eventType: "connection"),
                ],
                timeWindow: 300,
                correlationKey: .processPath,
                severity: .high,
                mitreId: "T1005 → T1560 → T1041",
                mitreName: "Collection → archive → exfiltration"
            ),

            // Environmental keying → payload drop → execution (conditional deployment)
            CorrelationRule(
                id: "corr_ns_keying_drop_exec",
                name: "Environment check → payload drop → execution",
                stages: [
                    RuleStage(
                        eventType: "auth_exec",
                        conditions: [
                            .processNameIn(["sysctl", "ioreg", "system_profiler"]),
                        ]
                    ),
                    RuleStage(
                        eventType: "file_write",
                        conditions: [
                            .fieldMatchesRegex("target_path", "(/tmp/|/var/tmp/|/var/folders/)"),
                        ]
                    ),
                    RuleStage(
                        eventType: "auth_exec",
                        conditions: [.processNotAppleSigned]
                    ),
                ],
                timeWindow: 120,
                correlationKey: .processPath,
                severity: .critical,
                mitreId: "T1497 → T1074 → T1204",
                mitreName: "Environmental keying → staging → execution"
            ),

            // Process hollowing chain: get_task → mprotect → execution from trusted path
            CorrelationRule(
                id: "corr_ns_hollow_chain",
                name: "Task port access → memory modify → suspicious execution",
                stages: [
                    RuleStage(eventType: "get_task", conditions: [.processNotAppleSigned]),
                    RuleStage(eventType: "mprotect"),
                    RuleStage(eventType: "connection"),
                ],
                timeWindow: 60,
                correlationKey: .pid,
                severity: .critical,
                mitreId: "T1055.012 → T1071",
                mitreName: "Process hollowing + C2 activation"
            ),

            // Privilege escalation chain: sudo → persistence → execution
            CorrelationRule(
                id: "corr_ns_privesc_persist",
                name: "Privilege escalation → persistence → payload",
                stages: [
                    RuleStage(eventType: "sudo", conditions: [.processNotAppleSigned]),
                    RuleStage(
                        eventType: "file_write",
                        conditions: [
                            .fieldMatchesRegex("target_path",
                                "(LaunchDaemons|com\\.apple\\.|/etc/)"),
                        ]
                    ),
                    RuleStage(eventType: "auth_exec", conditions: [.processNotAppleSigned]),
                ],
                timeWindow: 300,
                correlationKey: .processPath,
                severity: .critical,
                mitreId: "T1548 → T1543 → T1059",
                mitreName: "Privilege escalation → persistence → execution"
            ),

            // Defense evasion chain: kill security tool → drop payload → execute
            CorrelationRule(
                id: "corr_ns_kill_defender_exec",
                name: "Security tool kill → payload drop → execution",
                stages: [
                    RuleStage(
                        eventType: "auth_exec",
                        conditions: [
                            .processNameIn(["kill", "killall", "pkill"]),
                        ]
                    ),
                    RuleStage(
                        eventType: "file_write",
                        conditions: [.processNotAppleSigned]
                    ),
                    RuleStage(
                        eventType: "auth_exec",
                        conditions: [.processNotAppleSigned]
                    ),
                ],
                timeWindow: 60,
                correlationKey: .processPath,
                severity: .critical,
                mitreId: "T1562 → T1074 → T1204",
                mitreName: "Kill defender → drop → execute chain"
            ),
        ]
    }
}
