import Foundation
import os.log
import CryptoKit
import MachO

/// Detects process hollowing, in-memory code patching, and injected dylibs.
/// Nation-state actors inject code into legitimate Apple processes so it runs
/// under a trusted signature. This checker compares what's on disk to what's
/// actually loaded in memory.
public actor ProcessIntegrityChecker {
    public static let shared = ProcessIntegrityChecker()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "ProcessIntegrity")

    /// Check all running processes for integrity violations.
    /// System binaries (sealed volume) skip expensive dylib enum + __TEXT check —
    /// checkCodeSigningFlags still catches CS_DEBUGGED/CS_VALID anomalies cheaply.
    public func scan(snapshot: ProcessSnapshot? = nil) async -> [ProcessAnomaly] {
        let snap = snapshot ?? ProcessSnapshot.capture()
        var anomalies: [ProcessAnomaly] = []

        for pid in snap.pids {
            guard pid > 0 else { continue }
            let path = snap.path(for: pid)
            guard !path.isEmpty else { continue }

            let isSystem = path.hasPrefix("/System/") || path.hasPrefix("/usr/libexec/")
                || path.hasPrefix("/usr/sbin/") || path.hasPrefix("/usr/bin/")
                || path.hasPrefix("/sbin/")

            // 1. Injected dylibs — EXPENSIVE (task_for_pid + dyld image enum).
            // Skip for system binaries: sealed volume prevents tampering, dyld shared cache.
            if !isSystem {
                let injected = checkInjectedDylibs(pid: pid, binaryPath: path)
                anomalies.append(contentsOf: injected)
            }

            // 2. Code signing flags — CHEAP (proc_pidinfo + csops, ~2 syscalls). Always run.
            let csAnomalies = checkCodeSigningFlags(pid: pid, path: path)
            anomalies.append(contentsOf: csAnomalies)

            // 3. Binary hash — only checks system binaries, uses cached CodeSignValidator.
            let hashAnomaly = await checkBinaryHash(pid: pid, path: path)
            if let a = hashAnomaly { anomalies.append(a) }

            // 4. __TEXT integrity — EXPENSIVE (reads binary + task_for_pid + memory hash).
            // Skip for system binaries: sealed volume prevents disk tampering,
            // in-memory patching needs task_for_pid → caught by CS_DEBUGGED above.
            if !isSystem {
                if let textAnomaly = TextIntegrityChecker.check(pid: pid, binaryPath: path) {
                    anomalies.append(textAnomaly)
                }
            }
        }

        return anomalies.sorted { $0.severity > $1.severity }
    }

    /// Compare dylibs actually loaded in a process vs what the binary declares.
    /// Aggregates per-process — one finding with all undeclared dylibs, not one per dylib.
    /// System framework loads from sealed volume are whitelisted (can't be tampered).
    private func checkInjectedDylibs(pid: pid_t, binaryPath: String) -> [ProcessAnomaly] {
        let processName = URL(fileURLWithPath: binaryPath).lastPathComponent

        guard let machInfo = RustMachOParser.parse(binaryPath) else { return [] }

        // Build declared set from ALL load command types (load + weak + reexport)
        let allDeclared = machInfo.loadDylibs + machInfo.weakDylibs + machInfo.reexportDylibs
        let declaredNames = Set(allDeclared.map { dylibLeafName($0) })

        let enumResult = DylibEnumerator.loadedImagesWithMethod(for: pid)

        // Collect undeclared, non-system dylibs
        var undeclared: [String] = []
        for image in enumResult.images {
            if image == binaryPath { continue }
            // System libs from sealed volume / dyld shared cache — always expected
            if isSystemLibrary(image) { continue }
            let leaf = dylibLeafName(image)
            if !declaredNames.contains(leaf) {
                undeclared.append(image)
            }
        }

        guard !undeclared.isEmpty else { return [] }

        // Severity: unsigned non-system dylib = critical, signed third-party = medium
        let severity: AnomalySeverity = undeclared.count > 5 ? .critical : .high

        var evidence = [
            "injected_count: \(undeclared.count)",
            "declared_count: \(declaredNames.count)",
            "loaded_count: \(enumResult.images.count)",
            "enum_method: \(enumResult.method.rawValue)",
            "binary: \(binaryPath)",
        ]
        evidence += undeclared.prefix(10).map { "injected_dylib: \($0)" }
        if undeclared.count > 10 { evidence.append("... +\(undeclared.count - 10) more") }

        return [.forProcess(
            pid: pid, name: processName, path: binaryPath,
            technique: "Dylib Injection Detected",
            description: "\(processName) (PID \(pid)) has \(undeclared.count) non-system dylib(s) not declared in Mach-O headers.",
            severity: severity, mitreID: "T1055.001",
            scannerId: "process_integrity",
            enumMethod: enumResult.method == .dyld
                ? "task_info(TASK_DYLD_INFO) → dyld_all_image_infos"
                : "PROC_PIDREGIONPATHINFO",
            evidence: evidence
        )]
    }

    /// Check code signing flags for anomalies (two layers: proc_bsdinfo + csops kernel)
    private func checkCodeSigningFlags(pid: pid_t, path: String) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let processName = URL(fileURLWithPath: path).lastPathComponent

        // Layer 1: proc_bsdinfo flags
        var info = proc_bsdinfo()
        let size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard size > 0 else { return [] }

        let csFlags = info.pbi_flags
        let flagsHex = String(format: "0x%08X", csFlags)

        // Layer 2: Kernel CS flags via csops() syscall (deeper than proc_bsdinfo)
        let kernelCS = CodeSignValidator.kernelCSInfo(pid: pid)

        if csFlags & 0x0800 != 0 || kernelCS?.isDebugged == true {
            anomalies.append(.forProcess(
                pid: pid, name: processName, path: path,
                technique: "Process Has Been Debugged/Injected",
                description: "Process \(processName) (PID \(pid)) has CS_DEBUGGED flag. task_for_pid was used — possible code injection.",
                severity: .high, mitreID: "T1055",
                scannerId: "process_integrity",
                enumMethod: "csops(CS_OPS_STATUS) + proc_pidinfo(PROC_PIDTBSDINFO)",
                evidence: [
                    "pbi_flags: \(flagsHex)",
                    "kernel_cs: \(kernelCS?.flagsHex ?? "unavailable")",
                    "CS_DEBUGGED: SET",
                    "binary: \(path)",
                ]
            ))
        }

        // Any process running without CS_VALID — unsigned/tampered code running.
        // No path exemptions: a rootkit in /System/ with invalid CS is MORE suspicious.
        if let ks = kernelCS, !ks.isValid && !path.isEmpty {
            let isSystem = path.hasPrefix("/System/") || path.hasPrefix("/usr/lib/")
            anomalies.append(.forProcess(
                pid: pid, name: processName, path: path,
                technique: "Invalid Code Signature (Kernel)",
                description: "\(processName) (PID \(pid)) kernel reports CS_VALID=false.\(isSystem ? " SYSTEM BINARY — possible rootkit." : " Code signature invalid at kernel level.")",
                severity: .critical, mitreID: "T1036.001",
                scannerId: "process_integrity",
                enumMethod: "csops(CS_OPS_STATUS)",
                evidence: [
                    "kernel_cs: \(ks.flagsHex)",
                    "CS_VALID: false",
                    "is_system_path: \(isSystem)",
                    "flags: \(ks.flagDescriptions.joined(separator: ", "))",
                    "binary: \(path)",
                ]
            ))
        }

        if path.hasPrefix("/System/") || path.hasPrefix("/usr/") {
            if csFlags & 0x0100 == 0 && csFlags & 0x0200 == 0 {
                anomalies.append(.forProcess(
                    pid: pid, name: processName, path: path,
                    technique: "Missing Hardened Runtime Flags",
                    description: "System binary \(processName) missing CS_HARD|CS_KILL flags. May have been patched.",
                    severity: .high, mitreID: "T1574",
                    scannerId: "process_integrity",
                    enumMethod: "csops(CS_OPS_STATUS) + proc_pidinfo(PROC_PIDTBSDINFO)",
                    evidence: [
                        "pbi_flags: \(flagsHex)",
                        "kernel_cs: \(kernelCS?.flagsHex ?? "unavailable")",
                        "CS_HARD: \(csFlags & 0x0100 != 0 ? "SET" : "MISSING")",
                        "CS_KILL: \(csFlags & 0x0200 != 0 ? "SET" : "MISSING")",
                        "binary: \(path)",
                    ]
                ))
            }
        }

        return anomalies
    }

    /// Check if a system binary on disk has been modified (no time window — always flag).
    private func checkBinaryHash(pid: pid_t, path: String) async -> ProcessAnomaly? {
        let processName = URL(fileURLWithPath: path).lastPathComponent
        let isSystem = path.hasPrefix("/System/") || path.hasPrefix("/usr/")

        // System binaries: check if modified after OS install (no time limit)
        guard isSystem else { return nil }

        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: path),
              let modDate = attrs[.modificationDate] as? Date else { return nil }

        // Validate code signature — the ground truth for system binary integrity
        let signing = CodeSignValidator.validate(path: path)
        if !signing.isValidSignature {
            let fmt = DateFormatter()
            fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"
            return .forProcess(
                pid: pid, name: processName, path: path,
                technique: "Modified System Binary",
                description: "System binary \(path) has invalid signature. Possible rootkit or tampering.",
                severity: .critical, mitreID: "T1554",
                scannerId: "process_integrity",
                enumMethod: "SecStaticCodeCheckValidity + FileManager.attributesOfItem",
                evidence: [
                    "modified: \(fmt.string(from: modDate))",
                    "signature_valid: false",
                    "signing_id: \(signing.signingIdentifier ?? "none")",
                    "binary: \(path)",
                ]
            )
        }

        return nil
    }

    /// Extract leaf filename from a dylib path (strips @rpath/, @executable_path/, etc.)
    private func dylibLeafName(_ path: String) -> String {
        URL(fileURLWithPath: path).lastPathComponent
    }

    /// System libraries from the sealed system volume / dyld shared cache.
    /// These cannot be tampered with on modern macOS — always expected loads.
    private func isSystemLibrary(_ path: String) -> Bool {
        path.hasPrefix("/System/Library/") ||
        path.hasPrefix("/usr/lib/") ||
        path.hasPrefix("/System/iOSSupport/") ||
        path.hasPrefix("/System/Cryptexes/")
    }

}
