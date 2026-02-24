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
    /// ZERO-TRUST: no path-based skips. Expensive checks (task_for_pid) naturally
    /// fail on hardened system processes — no false positives, just honest scanning.
    public func scan(snapshot: ProcessSnapshot? = nil) async -> [ProcessAnomaly] {
        let snap = snapshot ?? ProcessSnapshot.capture()
        var anomalies: [ProcessAnomaly] = []

        for pid in snap.pids {
            guard pid > 0 else { continue }
            let path = snap.path(for: pid)
            guard !path.isEmpty else { continue }

            // 1. Injected dylibs (task_for_pid + dyld image enum).
            // task_for_pid fails on hardened processes → returns empty, no FP.
            let injected = checkInjectedDylibs(pid: pid, binaryPath: path)
            anomalies.append(contentsOf: injected)

            // 2. Code signing flags (proc_pidinfo + csops, ~2 syscalls). Always run.
            let csAnomalies = checkCodeSigningFlags(pid: pid, path: path)
            anomalies.append(contentsOf: csAnomalies)

            // 3. Binary hash — system binaries validated via SecStaticCodeCheckValidity.
            let hashAnomaly = await checkBinaryHash(pid: pid, path: path)
            if let a = hashAnomaly { anomalies.append(a) }

            // 4. __TEXT integrity (reads binary + task_for_pid + memory hash).
            // task_for_pid fails on hardened processes → returns nil, no FP.
            if let textAnomaly = TextIntegrityChecker.check(pid: pid, binaryPath: path) {
                anomalies.append(textAnomaly)
            }
        }

        return anomalies.sorted { $0.severity > $1.severity }
    }

    /// Compare dylibs actually loaded in a process vs what the binary declares.
    ///
    /// ZERO-TRUST: No process name allowlists. Detection is path-based:
    /// - System libraries (sealed volume): always expected, skip.
    /// - Dylibs from same .app bundle: framework loading, not injection.
    /// - Dylibs from staging dirs (/tmp/, /var/tmp/, /var/folders/): REAL INJECTION.
    /// - Dylibs from standard paths (/opt/, /Users/, /Applications/): dlopen() runtime loading.
    ///
    /// Why staging-only: DyldEnvDetector catches DYLD_INSERT_LIBRARIES.
    /// checkCodeSigningFlags catches CS_DEBUGGED (task_for_pid injection).
    /// This scanner's unique value: dylibs dropped in staging directories.
    private func checkInjectedDylibs(pid: pid_t, binaryPath: String) -> [ProcessAnomaly] {
        let processName = (binaryPath as NSString).lastPathComponent

        guard let machInfo = RustMachOParser.parse(binaryPath) else { return [] }

        let allDeclared = machInfo.loadDylibs + machInfo.weakDylibs + machInfo.reexportDylibs
        let declaredNames = Set(allDeclared.map { dylibLeafName($0) })

        let enumResult = DylibEnumerator.loadedImagesWithMethod(for: pid)
        let appBundle = extractAppBundlePath(binaryPath)

        var staged: [String] = []
        var externalCount = 0
        for image in enumResult.images {
            if image == binaryPath { continue }
            if isSystemLibrary(image) { continue }
            let leaf = dylibLeafName(image)
            if declaredNames.contains(leaf) { continue }
            if let bundle = appBundle, image.hasPrefix(bundle) { continue }

            // Staging directories: world-writable paths where attackers drop payloads
            if isStagingPath(image) {
                staged.append(image)
            } else {
                externalCount += 1
            }
        }

        guard !staged.isEmpty else { return [] }

        var evidence = [
            "staged_count: \(staged.count)",
            "external_undeclared: \(externalCount)",
            "declared_count: \(declaredNames.count)",
            "enum_method: \(enumResult.method.rawValue)",
            "binary: \(binaryPath)",
        ]
        evidence += staged.prefix(10).map { "staged_dylib: \($0)" }

        return [.forProcess(
            pid: pid, name: processName, path: binaryPath,
            technique: "Dylib Injection from Staging Directory",
            description: "\(processName) (PID \(pid)) has \(staged.count) undeclared dylib(s) from staging directories.",
            severity: .critical, mitreID: "T1055.001",
            scannerId: "process_integrity",
            enumMethod: enumResult.method == .dyld
                ? "task_info(TASK_DYLD_INFO) → dyld_all_image_infos"
                : "PROC_PIDREGIONPATHINFO",
            evidence: evidence
        )]
    }

    /// World-writable staging directories where attackers drop payloads
    private func isStagingPath(_ path: String) -> Bool {
        path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/")
            || path.hasPrefix("/var/tmp/") || path.hasPrefix("/private/var/tmp/")
            || path.hasPrefix("/var/folders/") || path.hasPrefix("/private/var/folders/")
    }

    /// Check code signing flags for anomalies (two layers: proc_bsdinfo + csops kernel)
    private func checkCodeSigningFlags(pid: pid_t, path: String) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let processName = (path as NSString).lastPathComponent

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

        // Contradiction-based CS_HARD|CS_KILL check for system binaries.
        // Apple doesn't set CS_HARD|CS_KILL on all system binaries — that's a
        // policy choice, not evidence of tampering. The real contradiction is:
        // kernel says CS_VALID=true (signature intact) but CS_HARD|CS_KILL missing
        // AND the binary's signature is INVALID on disk. That means someone removed
        // hardened flags post-signing.
        //
        // If CS_VALID is true, Apple's signing decision stands — no contradiction.
        if path.hasPrefix("/System/") || path.hasPrefix("/usr/") {
            if csFlags & 0x0100 == 0 && csFlags & 0x0200 == 0 {
                // Only flag if there's a contradiction: kernel says valid but
                // we can detect the signature was actually tampered with.
                if let ks = kernelCS, !ks.isValid {
                    anomalies.append(.forProcess(
                        pid: pid, name: processName, path: path,
                        technique: "Tampered System Binary (CS flags stripped)",
                        description: "System binary \(processName) missing CS_HARD|CS_KILL AND kernel reports invalid signature. Possible rootkit patch.",
                        severity: .critical, mitreID: "T1574",
                        scannerId: "process_integrity",
                        enumMethod: "csops(CS_OPS_STATUS) + proc_pidinfo(PROC_PIDTBSDINFO)",
                        evidence: [
                            "pbi_flags: \(flagsHex)",
                            "kernel_cs: \(ks.flagsHex)",
                            "CS_VALID: false",
                            "CS_HARD: MISSING",
                            "CS_KILL: MISSING",
                            "binary: \(path)",
                        ]
                    ))
                }
                // CS_VALID=true + missing CS_HARD|CS_KILL = Apple's policy, not a contradiction
            }
        }

        return anomalies
    }

    /// Check if a system binary on disk has been modified (no time window — always flag).
    private func checkBinaryHash(pid: pid_t, path: String) async -> ProcessAnomaly? {
        let processName = (path as NSString).lastPathComponent
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
        (path as NSString).lastPathComponent
    }

    /// Extract the .app bundle root from a binary path.
    /// e.g. "/Applications/Brave.app/Contents/MacOS/Brave" → "/Applications/Brave.app/"
    /// Returns nil if binary isn't inside an .app bundle.
    private func extractAppBundlePath(_ path: String) -> String? {
        guard let range = path.range(of: ".app/") else { return nil }
        return String(path[...range.upperBound])
    }

    /// Dyld shared cache paths — these dylibs are loaded via the shared cache,
    /// NOT via LC_LOAD_DYLIB, so they always appear "undeclared." Filtering them
    /// prevents false positives in the undeclared-dylib check.
    /// NOTE: On a compromised kernel, proc_pidinfo could report spoofed paths.
    /// This is a technical filter (dyld behavior), not a security trust assumption.
    private func isSystemLibrary(_ path: String) -> Bool {
        path.hasPrefix("/System/Library/") ||
        path.hasPrefix("/usr/lib/") ||
        path.hasPrefix("/System/iOSSupport/") ||
        path.hasPrefix("/System/Cryptexes/")
    }

}
