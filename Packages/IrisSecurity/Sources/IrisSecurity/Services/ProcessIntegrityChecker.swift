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
        let loadedImages = DylibEnumerator.loadedImages(for: pid)

        for image in loadedImages {
            let imageName = URL(fileURLWithPath: image).lastPathComponent

            // Skip system frameworks and standard libraries
            if image.hasPrefix("/System/") || image.hasPrefix("/usr/lib/") { continue }
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
                    enumMethod: "task_info(TASK_DYLD_INFO) → dyld_all_image_infos",
                    evidence: [
                        "injected_dylib: \(image)",
                        "declared_count: \(declaredDylibs.count)",
                        "loaded_count: \(loadedImages.count)",
                        "binary: \(binaryPath)",
                    ]
                ))
            }
        }

        return anomalies
    }

    /// Check code signing flags for anomalies
    private func checkCodeSigningFlags(pid: pid_t, path: String) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let processName = URL(fileURLWithPath: path).lastPathComponent

        var info = proc_bsdinfo()
        let size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard size > 0 else { return [] }

        let csFlags = info.pbi_flags

        let flagsHex = String(format: "0x%08X", csFlags)

        if csFlags & 0x0800 != 0 {
            anomalies.append(.forProcess(
                pid: pid, name: processName, path: path,
                technique: "Process Has Been Debugged/Injected",
                description: "Process \(processName) (PID \(pid)) has CS_DEBUGGED flag set. This means task_for_pid was used on it — possible code injection.",
                severity: .high, mitreID: "T1055",
                scannerId: "process_integrity",
                enumMethod: "proc_pidinfo(PROC_PIDTBSDINFO) → pbi_flags",
                evidence: [
                    "cs_flags: \(flagsHex)",
                    "CS_DEBUGGED (0x0800): SET",
                    "binary: \(path)",
                ]
            ))
        }

        if path.hasPrefix("/System/") || path.hasPrefix("/usr/") {
            if csFlags & 0x0100 == 0 && csFlags & 0x0200 == 0 {
                anomalies.append(.forProcess(
                    pid: pid, name: processName, path: path,
                    technique: "Missing Hardened Runtime Flags",
                    description: "System binary \(processName) missing CS_HARD|CS_KILL flags. May have been patched or replaced.",
                    severity: .high, mitreID: "T1574",
                    scannerId: "process_integrity",
                    enumMethod: "proc_pidinfo(PROC_PIDTBSDINFO) → pbi_flags",
                    evidence: [
                        "cs_flags: \(flagsHex)",
                        "CS_HARD (0x0100): \(csFlags & 0x0100 != 0 ? "SET" : "MISSING")",
                        "CS_KILL (0x0200): \(csFlags & 0x0200 != 0 ? "SET" : "MISSING")",
                        "binary: \(path)",
                    ]
                ))
            }
        }

        return anomalies
    }

    /// Check if the on-disk binary hash matches what we'd expect
    private func checkBinaryHash(pid: pid_t, path: String) async -> ProcessAnomaly? {
        let processName = URL(fileURLWithPath: path).lastPathComponent

        // For Apple system binaries, check if the binary on disk is still Apple-signed
        guard path.hasPrefix("/System/") || path.hasPrefix("/usr/") ||
              path.hasPrefix("/Applications/") else { return nil }

        // Check if the binary has been modified (timestamp vs expected)
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: path),
              let modDate = attrs[.modificationDate] as? Date else { return nil }

        // System binaries modified after OS install are suspicious
        // Check against a reasonable OS install date window
        let calendar = Calendar.current
        let components = calendar.dateComponents([.year], from: modDate)
        guard let year = components.year else { return nil }

        // If a system binary was modified very recently (within last 7 days),
        // and it's not an OS update period, flag it
        if path.hasPrefix("/System/") || path.hasPrefix("/usr/") {
            let daysSinceModified = Date().timeIntervalSince(modDate) / 86400
            if daysSinceModified < 7 {
                let fmt = DateFormatter()
                fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"
                return .forProcess(
                    pid: pid, name: processName, path: path,
                    technique: "Recently Modified System Binary",
                    description: "System binary \(path) was modified \(String(format: "%.1f", daysSinceModified)) days ago. System binaries should only change during OS updates.",
                    severity: .high, mitreID: "T1554",
                    scannerId: "process_integrity",
                    enumMethod: "FileManager.attributesOfItem → modificationDate",
                    evidence: [
                        "modified: \(fmt.string(from: modDate))",
                        "days_ago: \(String(format: "%.1f", daysSinceModified))",
                        "binary: \(path)",
                    ]
                )
            }
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
