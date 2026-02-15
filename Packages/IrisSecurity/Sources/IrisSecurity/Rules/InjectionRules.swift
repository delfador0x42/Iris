import Foundation

/// Rules for code injection detection: remote thread creation,
/// task port access, ptrace, kext loading, code signing invalidation.
public enum InjectionRules {

    public static func rules() -> [DetectionRule] {
        [
            // Remote thread creation by non-system process
            DetectionRule(
                id: "inject_remote_thread",
                name: "Remote thread created in another process",
                eventType: "remote_thread_create",
                conditions: [
                    .processNotAppleSigned,
                ],
                severity: .critical,
                mitreId: "T1055",
                mitreName: "Process Injection"
            ),
            // Task port access on non-child process
            DetectionRule(
                id: "inject_get_task",
                name: "Task port access (process injection vector)",
                eventType: "get_task",
                conditions: [
                    .processNotAppleSigned,
                ],
                severity: .high,
                mitreId: "T1055",
                mitreName: "Process Injection"
            ),
            // ptrace on another process (anti-debug or injection)
            DetectionRule(
                id: "inject_ptrace",
                name: "ptrace on another process",
                eventType: "ptrace",
                conditions: [
                    .processNotAppleSigned,
                    .processNameNotIn(["lldb", "debugserver", "dtrace"]),
                ],
                severity: .medium,
                mitreId: "T1055.008",
                mitreName: "Ptrace System Calls"
            ),
            // Non-Apple kext loading (Ventir, WeaponX)
            DetectionRule(
                id: "inject_kext_load",
                name: "Third-party kernel extension loaded",
                eventType: "kext_load",
                conditions: [
                    .processNotAppleSigned,
                ],
                severity: .critical,
                mitreId: "T1547.006",
                mitreName: "Kernel Modules and Extensions"
            ),
        ]
    }
}
