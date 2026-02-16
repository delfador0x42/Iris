import Foundation
import os.log

/// Scans process memory for RWX regions and suspicious memory layouts.
/// RWX = read-write-execute = shellcode. Legitimate only with JIT entitlement.
/// Covers hunt scripts: rwx_regions, vmmap_deep, thread_count.
public actor MemoryScanner {
    public static let shared = MemoryScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "MemoryScanner")

    /// JIT-entitled processes that legitimately use RWX
    private let jitProcesses = Set([
        "JavaScriptCore", "WebContent", "Safari", "Google Chrome Helper",
        "Firefox", "Brave Browser Helper", "Microsoft Edge Helper",
        "node", "deno", "bun", "qemu-system-aarch64", "qemu-system-x86_64",
    ])

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        for pid in snapshot.pids {
            let name = snapshot.name(for: pid)
            let path = snapshot.path(for: pid)
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/") { continue }
            anomalies.append(contentsOf: scanRWXRegions(pid: pid, name: name, path: path))
            anomalies.append(contentsOf: checkThreadCount(pid: pid, name: name, path: path))
        }
        return anomalies
    }

    /// Use proc_pidinfo to check for regions with rwx protection
    private func scanRWXRegions(pid: pid_t, name: String, path: String) -> [ProcessAnomaly] {
        if jitProcesses.contains(name) { return [] }

        guard let output = runCmd("/usr/bin/vmmap", args: ["-summary", "\(pid)"]) else { return [] }

        var rwxCount = 0
        for line in output.split(separator: "\n") {
            let s = String(line)
            // Look for regions with r-x or rwx in the protection column
            if s.contains("r-x/rwx") || s.contains("rwx/rwx") {
                if !s.contains("MALLOC") && !s.contains("__TEXT") {
                    rwxCount += 1
                }
            }
        }

        if rwxCount > 0 {
            return [.forProcess(
                pid: pid, name: name, path: path,
                technique: "RWX Memory Regions",
                description: "\(name) has \(rwxCount) RWX memory region(s). Potential shellcode or injected code.",
                severity: .high, mitreID: "T1055.012",
                scannerId: "memory",
                enumMethod: "vmmap -summary",
                evidence: [
                    "pid: \(pid)",
                    "rwx_region_count: \(rwxCount)",
                    "process: \(name)",
                ])]
        }
        return []
    }

    /// High thread count may indicate injection (injected threads)
    private func checkThreadCount(pid: pid_t, name: String, path: String) -> [ProcessAnomaly] {
        var info = proc_taskinfo()
        let size = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &info, Int32(MemoryLayout<proc_taskinfo>.size))
        guard size > 0 else { return [] }
        let threads = Int(info.pti_threadnum)

        if threads > 100 {
            return [.forProcess(
                pid: pid, name: name, path: path,
                technique: "Anomalous Thread Count",
                description: "\(name) has \(threads) threads. May indicate thread injection or mining.",
                severity: .medium, mitreID: "T1055",
                scannerId: "memory",
                enumMethod: "proc_pidinfo(PROC_PIDTASKINFO)",
                evidence: [
                    "pid: \(pid)",
                    "thread_count: \(threads)",
                    "threshold: 100",
                ])]
        }
        return []
    }

    private func runCmd(_ path: String, args: [String]) -> String? {
        let proc = Process(); proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        let pipe = Pipe(); proc.standardOutput = pipe; proc.standardError = pipe
        try? proc.run(); proc.waitUntilExit()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
    }
}
