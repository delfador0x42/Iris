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

    /// Check all running processes for integrity violations
    public func scan(snapshot: ProcessSnapshot? = nil) async -> [ProcessAnomaly] {
        let snap = snapshot ?? ProcessSnapshot.capture()
        var anomalies: [ProcessAnomaly] = []

        for pid in snap.pids {
            guard pid > 0 else { continue }
            let path = snap.path(for: pid)
            guard !path.isEmpty else { continue }

            // 1. Check for injected dylibs (dylibs loaded that weren't in the binary)
            let injected = checkInjectedDylibs(pid: pid, binaryPath: path)
            anomalies.append(contentsOf: injected)

            // 2. Check code signing flags anomalies
            let csAnomalies = checkCodeSigningFlags(pid: pid, path: path)
            anomalies.append(contentsOf: csAnomalies)

            // 3. Check for processes with mismatched binary hash
            let hashAnomaly = await checkBinaryHash(pid: pid, path: path)
            if let a = hashAnomaly { anomalies.append(a) }

            // 4. __TEXT integrity: compare on-disk vs in-memory (process hollowing)
            if let textAnomaly = TextIntegrityChecker.check(pid: pid, binaryPath: path) {
                anomalies.append(textAnomaly)
            }
        }

        return anomalies.sorted { $0.severity > $1.severity }
    }

    /// Compare dylibs actually loaded in a process vs what the binary declares
    private func checkInjectedDylibs(pid: pid_t, binaryPath: String) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let processName = URL(fileURLWithPath: binaryPath).lastPathComponent

        // Get dylibs declared in Mach-O
        guard let machInfo = RustMachOParser.parse(binaryPath) else { return [] }
        let declaredDylibs = Set(machInfo.loadDylibs.map { resolveDylibPath($0) })

        // Get dylibs actually loaded (TASK_DYLD_INFO primary, VM regions fallback)
        let enumResult = DylibEnumerator.loadedImagesWithMethod(for: pid)
        let loadedImages = enumResult.images

        for image in loadedImages {
            let imageName = URL(fileURLWithPath: image).lastPathComponent

            if image == binaryPath { continue }

            // Check if this dylib was declared in the binary
            let isDeclared = declaredDylibs.contains { declared in
                image.hasSuffix(declared) || declared.hasSuffix(imageName)
            }

            if !isDeclared {
                anomalies.append(.forProcess(
                    pid: pid, name: processName, path: binaryPath,
                    technique: "Dylib Injection Detected",
                    description: "Process \(processName) (PID \(pid)) has loaded \(image) which is NOT declared in its Mach-O headers. Possible DYLD_INSERT_LIBRARIES or task_for_pid injection.",
                    severity: .critical, mitreID: "T1055.001",
                    scannerId: "process_integrity",
                    enumMethod: enumResult.method == .dyld
                        ? "task_info(TASK_DYLD_INFO) → dyld_all_image_infos"
                        : "PROC_PIDREGIONPATHINFO (incomplete — shared cache missed)",
                    evidence: [
                        "injected_dylib: \(image)",
                        "enum_method: \(enumResult.method.rawValue)",
                        "declared_count: \(declaredDylibs.count)",
                        "loaded_count: \(loadedImages.count)",
                        "binary: \(binaryPath)",
                    ]
                ))
            }
        }

        return anomalies
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

    private func resolveDylibPath(_ path: String) -> String {
        // Strip @rpath/, @executable_path/, etc — just get the filename
        if let lastSlash = path.lastIndex(of: "/") {
            return String(path[path.index(after: lastSlash)...])
        }
        return path
    }

}
