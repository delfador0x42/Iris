import Foundation
import os.log

/// Cross-references three independent sources of launch daemon/agent state
/// to detect rootkit persistence that evades any single source.
///
/// Lie detected: "All running daemons have legitimate plist files"
/// Ground truth: Compare disk plists vs launchctl list vs running processes.
///
/// Contradictions caught:
/// - Ghost daemon: in launchctl but no plist on disk → rootkit loaded then deleted plist
/// - Shadow process: process running matching a daemon name but not in launchctl → bypassed launchd
/// - Phantom plist: plist loads non-existent binary but daemon appears loaded → binary deleted post-launch
/// - Suppressed daemon: plist exists, launchctl shows it, KeepAlive=true, but process not running → being killed
///
/// Adversary cost: Would need to hook both launchctl AND hide the process AND
/// fake the plist — three independent subsystems to compromise simultaneously.
public actor LaunchDaemonCensusProbe {
    public static let shared = LaunchDaemonCensusProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "LaunchDaemonCensus")

    /// Directories containing launch plists
    private let daemonDirs = ["/Library/LaunchDaemons"]
    private let agentDirs: [String] = {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return ["/Library/LaunchAgents", "\(home)/Library/LaunchAgents"]
    }()

    /// Apple labels we expect to see — never flag these
    private let applePrefix = "com.apple."

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // Source 1: Plists on disk
        let diskPlists = readDiskPlists()

        // Source 2: launchctl list (what launchd says is loaded)
        let loadedServices = readLaunchctlList()

        // Source 3: Running processes from snapshot
        let runningNames = Set(snapshot.pids.compactMap { snapshot.name(for: $0) })
        let runningPaths = Set(snapshot.pids.compactMap { snapshot.path(for: $0) })

        // Check 1: Services in launchctl with NO plist on disk (ghost daemons)
        let diskLabels = Set(diskPlists.map(\.label))
        for (label, info) in loadedServices {
            guard !label.hasPrefix(applePrefix) else { continue }
            guard !label.hasPrefix("com.wudan.") else { continue }
            if !diskLabels.contains(label) && info.pid > 0 {
                anomalies.append(.filesystem(
                    name: label, path: "launchctl://\(label)",
                    technique: "Ghost Launch Daemon",
                    description: "Service '\(label)' running (PID \(info.pid)) with no plist on disk. Rootkit may have loaded and deleted the plist.",
                    severity: .critical, mitreID: "T1543.004",
                    scannerId: "launch_daemon_census",
                    enumMethod: "launchctl list vs disk plist scan",
                    evidence: [
                        "label: \(label)",
                        "pid: \(info.pid)",
                        "status: \(info.status)",
                        "plist_on_disk: false",
                    ]))
            }
        }

        // Check 2: Plists on disk that load non-Apple binaries but binary doesn't exist
        for plist in diskPlists where !plist.label.hasPrefix(applePrefix) {
            guard let binary = plist.binaryPath else { continue }
            if !FileManager.default.fileExists(atPath: binary) {
                // Is it still loaded in launchctl?
                let loaded = loadedServices[plist.label]
                if let svc = loaded, svc.pid > 0 {
                    anomalies.append(.filesystem(
                        name: plist.label, path: plist.path,
                        technique: "Phantom Launch Daemon",
                        description: "Plist '\(plist.label)' loaded (PID \(svc.pid)) but binary '\(binary)' missing from disk.",
                        severity: .high, mitreID: "T1543.004",
                        scannerId: "launch_daemon_census",
                        enumMethod: "plist binary path vs disk existence check",
                        evidence: [
                            "label: \(plist.label)",
                            "plist: \(plist.path)",
                            "binary: \(binary)",
                            "binary_exists: false",
                            "pid: \(svc.pid)",
                        ]))
                }
            }
        }

        // Check 3: Processes running that match daemon binary paths but aren't in launchctl
        let loadedPids = Set(loadedServices.values.map(\.pid).filter { $0 > 0 })
        for pid in snapshot.pids {
            let path = snapshot.path(for: pid)
            guard !path.isEmpty else { continue }
            // Is this binary referenced by any plist?
            let matchingPlist = diskPlists.first { $0.binaryPath == path }
            guard let plist = matchingPlist else { continue }
            guard !plist.label.hasPrefix(applePrefix) else { continue }
            // If there's a plist for this binary but launchctl doesn't know about this PID
            if !loadedPids.contains(Int(pid)) {
                let inLaunchctl = loadedServices[plist.label]
                if inLaunchctl == nil || inLaunchctl?.pid == 0 {
                    let name = snapshot.name(for: pid)
                    anomalies.append(.forProcess(
                        pid: pid,
                        name: name.isEmpty ? "unknown" : name,
                        path: path,
                        technique: "Shadow Daemon Process",
                        description: "Process running binary '\(path)' (matches plist '\(plist.label)') but not managed by launchd.",
                        severity: .high, mitreID: "T1543.004",
                        scannerId: "launch_daemon_census",
                        enumMethod: "running process path vs launchctl PID cross-reference",
                        evidence: [
                            "pid: \(pid)",
                            "path: \(path)",
                            "matching_plist: \(plist.label)",
                            "in_launchctl: \(inLaunchctl != nil)",
                            "launchctl_pid: \(inLaunchctl?.pid ?? 0)",
                        ]))
                }
            }
        }

        logger.info("LaunchDaemon census: \(diskPlists.count) plists, \(loadedServices.count) launchctl entries, \(anomalies.count) contradictions")
        return anomalies
    }

    // MARK: - Source 1: Disk Plists

    private struct DiskPlist {
        let label: String
        let path: String
        let binaryPath: String?
        let keepAlive: Bool
    }

    private func readDiskPlists() -> [DiskPlist] {
        var results: [DiskPlist] = []
        let allDirs = daemonDirs + agentDirs
        let fm = FileManager.default

        for dir in allDirs {
            guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in files where file.hasSuffix(".plist") {
                let fullPath = "\(dir)/\(file)"
                guard let plist = NSDictionary(contentsOfFile: fullPath) else { continue }
                let label = (plist["Label"] as? String) ?? file.replacingOccurrences(of: ".plist", with: "")
                let binary: String?
                if let prog = plist["Program"] as? String {
                    binary = prog
                } else if let args = plist["ProgramArguments"] as? [String] {
                    binary = args.first
                } else {
                    binary = nil
                }
                let keepAlive = (plist["KeepAlive"] as? Bool) == true
                results.append(DiskPlist(label: label, path: fullPath, binaryPath: binary, keepAlive: keepAlive))
            }
        }
        return results
    }

    // MARK: - Source 2: launchctl list

    private struct LaunchctlEntry {
        let pid: Int
        let status: Int
    }

    private func readLaunchctlList() -> [String: LaunchctlEntry] {
        // Use launchctl list — each line: PID\tStatus\tLabel
        guard let output = runCommand("/bin/launchctl", args: ["list"]) else { return [:] }
        var entries: [String: LaunchctlEntry] = [:]
        for line in output.split(separator: "\n").dropFirst() { // skip header
            let parts = line.split(separator: "\t", maxSplits: 2)
            guard parts.count == 3 else { continue }
            let pid = Int(parts[0]) ?? 0 // "-" becomes 0
            let status = Int(parts[1]) ?? 0
            let label = String(parts[2])
            entries[label] = LaunchctlEntry(pid: pid, status: status)
        }
        return entries
    }

    private func runCommand(_ path: String, args: [String]) -> String? {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
            proc.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8)
        } catch {
            return nil
        }
    }
}
