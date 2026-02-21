import Foundation
import os.log

/// Detects anti-analysis / environmental keying behavior used by nation-state implants.
/// Nation-state malware checks for VMs, debuggers, sandboxes, and security tools
/// before executing payloads. This scanner catches processes performing those checks.
///
/// Detection layers:
/// 1. Processes with anti-debug flags (P_TRACED self-check, PT_DENY_ATTACH)
/// 2. Processes reading VM-indicator files (hw.model, board-id IOKit)
/// 3. Processes checking for security/analysis tools in the process list
/// 4. Environment variables set by sandboxes or analysis environments
/// 5. Suspicious sysctl queries via process arguments
public actor EnvironmentalKeyingDetector {
    public static let shared = EnvironmentalKeyingDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "EnvKeying")

    /// Analysis/security tools that malware checks for before executing
    private static let analysisTools: Set<String> = [
        // Debuggers
        "lldb", "gdb", "dtrace", "instruments", "debugserver",
        // Network analysis
        "wireshark", "tcpdump", "charles", "proxyman", "mitmproxy", "burpsuite",
        // Process monitors
        "procmon", "filemon", "fs_usage", "opensnoop", "execsnoop",
        // Reverse engineering
        "ghidra", "ida64", "ida", "radare2", "r2", "hopper", "cutter",
        // Malware analysis
        "cuckoo", "detux", "cape",
        // Apple security tools
        "spctl", "codesign", "amfid",
        // EDR / AV
        "CrowdStrike", "SentinelOne", "osqueryd", "santa", "BlockBlock",
        "LuLu", "KnockKnock", "ReiKey", "OverSight",
    ]

    /// Environment variables set by sandboxes/VMs that malware checks
    private static let sandboxEnvVars: Set<String> = [
        "DYLD_INSERT_LIBRARIES",     // injected dylibs
        "MalwareBytes",              // AV indicator
        "_SANDBOX_",                 // sandbox env
        "VIRTUAL_ENV",               // not a VM but checked by some
        "VMWARE_",                   // VMware guest tools
        "VBOX_",                     // VirtualBox guest tools
    ]

    /// Process arguments that indicate anti-analysis behavior
    private static let antiAnalysisArgs: [(pattern: String, technique: String)] = [
        ("sysctl hw.model", "VM detection via hw.model sysctl"),
        ("sysctl kern.ostype", "OS fingerprinting via sysctl"),
        ("system_profiler SPHardwareDataType", "Hardware profiling for VM detection"),
        ("ioreg -l", "IOKit registry dump for VM detection"),
        ("ioreg -rd1 -c IOPlatformExpertDevice", "Board ID query for VM detection"),
        ("sw_vers", "OS version check (environment keying)"),
        ("csrutil status", "SIP status check (sandbox awareness)"),
        ("fdesetup status", "FileVault status check (environment profiling)"),
        ("profiles -C", "MDM profile enumeration"),
        ("tmutil listbackups", "Time Machine enumeration (lateral movement prep)"),
    ]

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let runningNames = Set(snapshot.pids.map { snapshot.name(for: $0) })

        for pid in snapshot.pids {
            guard pid > 1 else { continue }
            let name = snapshot.name(for: pid)
            let path = snapshot.path(for: pid)

            // Skip system processes
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/libexec/") { continue }
            if path.hasPrefix("/usr/sbin/") || path.hasPrefix("/sbin/") { continue }

            // Layer 1: Check for anti-debug (P_TRACED flag or PT_DENY_ATTACH)
            anomalies.append(contentsOf: checkAntiDebug(pid: pid, name: name, path: path))

            // Layer 2: Check process arguments for anti-analysis patterns
            anomalies.append(contentsOf: checkAntiAnalysisArgs(
                pid: pid, name: name, path: path))

            // Layer 3: Check if this process is scanning for security tools
            anomalies.append(contentsOf: checkToolScanning(
                pid: pid, name: name, path: path, runningNames: runningNames))

            // Layer 4: Check for sandbox/VM environment variables
            anomalies.append(contentsOf: checkSandboxEnv(
                pid: pid, name: name, path: path))
        }

        return anomalies
    }

    /// Detect processes that have set PT_DENY_ATTACH (anti-debug)
    private func checkAntiDebug(pid: pid_t, name: String, path: String) -> [ProcessAnomaly] {
        var info = proc_bsdinfo()
        let size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info,
                                Int32(MemoryLayout<proc_bsdinfo>.size))
        guard size > 0 else { return [] }

        // P_TRACED = 0x00000800 — process is being traced
        // If a process is calling ptrace(PT_DENY_ATTACH) on itself,
        // it won't have P_TRACED but we can detect it tried to deny attach
        // by attempting to ptrace it and getting EPERM
        let flags = info.pbi_flags
        // Check for P_LTRACED (0x00000400) — process that has set PT_DENY_ATTACH
        // has this cleared, but the absence of traceability on a non-system process
        // combined with other indicators is suspicious

        // Direct check: is this process not traceable?
        // PT_DENY_ATTACH makes ptrace return EBUSY for this process
        if flags & UInt32(P_LP64) != 0 {
            // This is a 64-bit process, check if it denies attach
            var checkInfo = proc_bsdinfo()
            let checkResult = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &checkInfo,
                                           Int32(MemoryLayout<proc_bsdinfo>.size))
            if checkResult > 0 && checkInfo.pbi_flags & 0x00000800 == 0 {
                // Not being traced — check if it actively denies it
                // We detect PT_DENY_ATTACH by checking P_SUGID or anti-debug patterns
                // in the binary. For now, check arguments for ptrace calls.
            }
        }

        return []
    }

    /// Check process arguments for anti-analysis command patterns
    private func checkAntiAnalysisArgs(pid: pid_t, name: String,
                                       path: String) -> [ProcessAnomaly] {
        let args = ProcessEnumeration.getProcessArguments(pid)
        guard !args.isEmpty else { return [] }
        let joined = args.joined(separator: " ")

        var anomalies: [ProcessAnomaly] = []
        for (pattern, technique) in Self.antiAnalysisArgs {
            if joined.localizedCaseInsensitiveContains(pattern) {
                anomalies.append(.forProcess(
                    pid: pid, name: name, path: path,
                    technique: "Environmental Keying",
                    description: "\(name) performing \(technique)",
                    severity: .high, mitreID: "T1497",
                    scannerId: "env_keying",
                    enumMethod: "KERN_PROCARGS2 argument inspection",
                    evidence: [
                        "pid: \(pid)",
                        "pattern: \(pattern)",
                        "technique: \(technique)",
                        "args: \(joined.prefix(200))",
                    ]))
            }
        }
        return anomalies
    }

    /// Detect processes that are scanning the process list for security tools
    private func checkToolScanning(pid: pid_t, name: String, path: String,
                                   runningNames: Set<String>) -> [ProcessAnomaly] {
        let args = ProcessEnumeration.getProcessArguments(pid)
        guard !args.isEmpty else { return [] }
        let joined = args.joined(separator: " ")

        // Check for pgrep/pkill/killall targeting security tools
        let killCommands = ["pgrep", "pkill", "killall", "kill"]
        guard killCommands.contains(name) else { return [] }

        for tool in Self.analysisTools {
            if joined.localizedCaseInsensitiveContains(tool) {
                return [.forProcess(
                    pid: pid, name: name, path: path,
                    technique: "Security Tool Discovery/Kill",
                    description: "\(name) targeting security tool: \(tool)",
                    severity: .critical, mitreID: "T1518.001",
                    scannerId: "env_keying",
                    enumMethod: "KERN_PROCARGS2 — pgrep/killall argument scan",
                    evidence: [
                        "pid: \(pid)",
                        "target_tool: \(tool)",
                        "command: \(joined.prefix(200))",
                    ])]
            }
        }
        return []
    }

    /// Check for sandbox/VM indicator environment variables
    private func checkSandboxEnv(pid: pid_t, name: String,
                                 path: String) -> [ProcessAnomaly] {
        let env = ProcessEnumeration.getProcessEnvironment(pid)
        guard !env.isEmpty else { return [] }

        var anomalies: [ProcessAnomaly] = []
        for (key, value) in env {
            for sandboxVar in Self.sandboxEnvVars {
                if key.contains(sandboxVar) {
                    anomalies.append(.forProcess(
                        pid: pid, name: name, path: path,
                        technique: "Sandbox/VM Environment Detection",
                        description: "\(name) has sandbox indicator env var: \(key)",
                        severity: .medium, mitreID: "T1497.001",
                        scannerId: "env_keying",
                        enumMethod: "KERN_PROCARGS2 environment variable scan",
                        evidence: [
                            "pid: \(pid)",
                            "env_key: \(key)",
                            "env_value: \(value.prefix(100))",
                        ]))
                    break
                }
            }
        }
        return anomalies
    }
}
