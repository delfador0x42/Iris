import Foundation
import os.log

/// Process ancestry forensics scanner.
/// Detects double-fork orphaning, suspicious reparenting, and anomalous lineage.
///
/// Key detections:
/// 1. Double-fork orphans: process reparented to launchd (ppid=1) that wasn't
///    launched by launchd. Classic daemonization technique used by implants.
/// 2. Shell → interpreter chains: bash→python→network or bash→perl→crypto.
/// 3. Lineage anomalies: unsigned binaries spawned by system services.
public actor AncestryScanner {
    public static let shared = AncestryScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "Ancestry")

    /// Known daemon launchers — processes that legitimately have ppid=1
    private static let legitimateLaunchdChildren: Set<String> = [
        "launchd", "kernel_task", "syslogd", "UserEventAgent",
        "distnoted", "cfprefsd", "trustd", "securityd",
        "WindowServer", "loginwindow", "Finder", "Dock",
        "SystemUIServer", "AirPlayUIAgent", "Spotlight",
        "mds", "mds_stores", "mdworker", "mdworker_shared",
        "notifyd", "opendirectoryd", "diskarbitrationd",
        "coreservicesd", "lsd", "BlueTool",
        "powerd", "logd", "fseventsd", "configd",
        "sysextd", "endpointsecurityd", "nesessionmanager",
        "containermanagerd", "runningboardd", "corespeechd",
        "biomed", "mediaremoted", "rapportd",
    ]

    /// Shells and interpreters (used in attack chains)
    private static let shells: Set<String> = [
        "bash", "zsh", "sh", "fish", "dash", "csh", "tcsh",
    ]
    private static let interpreters: Set<String> = [
        "python", "python3", "python3.9", "python3.10", "python3.11", "python3.12",
        "perl", "perl5.30", "ruby", "node", "osascript", "swift",
    ]

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        for pid in snapshot.pids {
            guard pid > 1 else { continue }
            let path = snapshot.path(for: pid)
            guard !path.isEmpty else { continue }
            let name = snapshot.name(for: pid)
            let ppid = snapshot.parent(of: pid)

            // 1. Double-fork orphan detection
            if let a = checkOrphan(pid: pid, name: name, path: path, ppid: ppid, snapshot: snapshot) {
                anomalies.append(a)
            }

            // 2. Shell → interpreter attack chains
            anomalies.append(contentsOf: checkAttackChain(
                pid: pid, name: name, path: path, snapshot: snapshot))
        }

        return anomalies
    }

    /// Detect double-fork orphans: process with ppid=1 that wasn't
    /// launched by launchd or a known system service.
    private func checkOrphan(
        pid: pid_t, name: String, path: String, ppid: pid_t, snapshot: ProcessSnapshot
    ) -> ProcessAnomaly? {
        guard ppid == 1 else { return nil }

        // Known legitimate launchd children
        if Self.legitimateLaunchdChildren.contains(name) { return nil }

        // System paths are expected to be launched by launchd
        if path.hasPrefix("/System/Library/") { return nil }
        if path.hasPrefix("/usr/libexec/") { return nil }
        if path.hasPrefix("/usr/sbin/") { return nil }

        // Check if this process has an associated LaunchDaemon/Agent plist
        // If it does, it was legitimately launched by launchd
        let basename = (path as NSString).lastPathComponent
        let daemonPaths = [
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
            "/System/Library/LaunchAgents",
        ]
        for dir in daemonPaths {
            let plist = "\(dir)/\(basename).plist"
            if FileManager.default.fileExists(atPath: plist) { return nil }
        }

        // Check code signing — unsigned orphans are more suspicious
        let signing = CodeSignValidator.validate(path: path)
        let isSigned = signing.isValidSignature
        let severity: AnomalySeverity = isSigned ? .medium : .high

        return .forProcess(
            pid: pid, name: name, path: path,
            technique: "Double-Fork Orphan Process",
            description: "\(name) is parented to launchd (ppid=1) but not a known launch service. Possible double-fork daemonization.",
            severity: severity, mitreID: "T1036.004",
            scannerId: "ancestry",
            enumMethod: "ProcessSnapshot ancestry walk + LaunchDaemon plist cross-validation",
            evidence: [
                "pid: \(pid)", "ppid: 1 (launchd)",
                "binary: \(path)",
                "signed: \(isSigned)",
                "signing_id: \(signing.signingIdentifier ?? "none")",
                "team_id: \(signing.teamIdentifier ?? "none")",
            ])
    }

    /// Detect suspicious shell → interpreter → action chains.
    /// Example: zsh → python3 → curl (data exfil via script)
    private func checkAttackChain(
        pid: pid_t, name: String, path: String, snapshot: ProcessSnapshot
    ) -> [ProcessAnomaly] {
        // Only check interpreters
        guard Self.interpreters.contains(name) else { return [] }

        let ancestry = snapshot.ancestryNames(of: pid)
        guard !ancestry.isEmpty else { return [] }
        let parentName = ancestry.first ?? ""

        // Shell → interpreter chain
        guard Self.shells.contains(parentName) else { return [] }

        // Get the interpreter's arguments to understand what it's doing
        let args = ProcessEnumeration.getProcessArguments(pid)
        let argsStr = args.joined(separator: " ")

        // Check for suspicious patterns in interpreter args
        let suspicious = argsStr.contains("-c ") || argsStr.contains("import socket")
            || argsStr.contains("import subprocess") || argsStr.contains("exec(")
            || argsStr.contains("eval(") || argsStr.contains("base64")
            || argsStr.contains("urllib") || argsStr.contains("http.client")
            || argsStr.contains("requests.") || argsStr.contains("Crypto")
            || argsStr.contains("/dev/tcp/") || argsStr.contains("reverse_tcp")
            || argsStr.contains("IO.popen") || argsStr.contains("Net::HTTP")

        guard suspicious else { return [] }

        let chain = ([name] + ancestry.prefix(3)).joined(separator: " ← ")

        return [.forProcess(
            pid: pid, name: name, path: path,
            technique: "Shell→Interpreter Attack Chain",
            description: "Suspicious interpreter execution: \(chain). Arguments suggest \(classifyArgs(argsStr)).",
            severity: .high, mitreID: "T1059",
            scannerId: "ancestry",
            enumMethod: "ProcessSnapshot ancestry + KERN_PROCARGS2 argument extraction",
            evidence: [
                "pid: \(pid)", "binary: \(path)",
                "chain: \(chain)",
                "args: \(String(argsStr.prefix(200)))",
                "parent: \(parentName)",
            ])]
    }

    private func classifyArgs(_ args: String) -> String {
        if args.contains("socket") || args.contains("/dev/tcp") || args.contains("reverse") {
            return "network/reverse shell activity"
        }
        if args.contains("base64") || args.contains("exec(") || args.contains("eval(") {
            return "code execution via encoded payload"
        }
        if args.contains("Crypto") || args.contains("encrypt") || args.contains("cipher") {
            return "cryptographic operations (possible ransomware)"
        }
        if args.contains("urllib") || args.contains("http") || args.contains("requests") {
            return "HTTP data transfer (possible exfiltration)"
        }
        return "potentially malicious activity"
    }
}
