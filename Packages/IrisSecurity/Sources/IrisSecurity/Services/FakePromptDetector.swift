import Foundation
import os.log

/// Detects osascript password phishing — the #1 credential theft technique on macOS.
/// Used by: Atomic Stealer, Banshee, Cuckoo, Poseidon, and virtually all 2024 stealers.
/// Covers hunt scripts: fake_prompts.
public actor FakePromptDetector {
    public static let shared = FakePromptDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "FakePrompt")

    /// Known-safe signing IDs that legitimately use osascript
    private let safeParents = Set([
        "com.apple.automator", "com.apple.ScriptEditor2",
        "com.apple.shortcuts", "com.jamf.management.jamfAgent",
        "com.microsoft.office", "com.barebones.bbedit",
    ])

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        for pid in snapshot.pids {
            let name = snapshot.name(for: pid)
            guard name == "osascript" || name == "Script Editor" else { continue }
            let path = snapshot.path(for: pid)

            // Get command-line arguments
            let args = ProcessEnumeration.getProcessArguments(pid)
            let argString = args.joined(separator: " ").lowercased()

            // Check for password dialog patterns
            let phishingPatterns = [
                "display dialog",     // base pattern
                "hidden answer",      // masks the password input
                "default answer",     // captures text input
                "with icon caution",  // makes it look like a system alert
                "system preferences", // masquerades as system
                "system settings",    // macOS 13+ name
                "update required",    // fake update prompt
                "password",           // explicit password request
                "administrator privileges", // social engineering
            ]

            var matched: [String] = []
            for pattern in phishingPatterns where argString.contains(pattern) {
                matched.append(pattern)
            }

            if matched.count >= 2 { // require 2+ patterns to reduce false positives
                let parentPid = snapshot.parents[pid] ?? 0
                let parentName = snapshot.name(for: parentPid)

                anomalies.append(ProcessAnomaly(
                    pid: pid, processName: name, processPath: path,
                    parentPID: parentPid, parentName: parentName,
                    technique: "Fake Password Prompt",
                    description: "osascript running password phishing dialog (matched: \(matched.joined(separator: ", "))). Parent: \(parentName).",
                    severity: .critical, mitreID: "T1056.002",
                    scannerId: "fake_prompt",
                    enumMethod: "sysctl(KERN_PROCARGS2) argument parsing",
                    evidence: [
                        "pid: \(pid)",
                        "matched_patterns: \(matched.joined(separator: ", "))",
                        "parent: \(parentName) (PID \(parentPid))",
                    ]
                ))
            }

            // Also flag osascript spawned from /tmp or /Users/Shared
            if path.hasPrefix("/tmp/") || path.hasPrefix("/var/tmp/") ||
               path.hasPrefix("/Users/Shared/") {
                anomalies.append(.forProcess(
                    pid: pid, name: name, path: path,
                    technique: "osascript from Temp",
                    description: "osascript running from suspicious location: \(path)",
                    severity: .high, mitreID: "T1059.002",
                    scannerId: "fake_prompt",
                    enumMethod: "ProcessSnapshot path inspection",
                    evidence: [
                        "pid: \(pid)",
                        "path: \(path)",
                        "process: \(name)",
                    ]
                ))
            }
        }
        return anomalies
    }
}
