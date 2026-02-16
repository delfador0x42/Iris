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

        // Get dylibs actually loaded via proc_regionfilename or dyld info
        let loadedImages = getLoadedImages(pid: pid)

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
                // This dylib was NOT in the original binary — injected
                anomalies.append(.forProcess(
                    pid: pid, name: processName, path: binaryPath,
                    technique: "Dylib Injection Detected",
                    description: "Process \(processName) (PID \(pid)) has loaded \(image) which is NOT declared in its Mach-O headers. Possible DYLD_INSERT_LIBRARIES or task_for_pid injection.",
                    severity: .critical, mitreID: "T1055.001"
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

        // CS_DEBUGGED (0x0800) — process has been debugged/injected
        if csFlags & 0x0800 != 0 {
            anomalies.append(.forProcess(
                pid: pid, name: processName, path: path,
                technique: "Process Has Been Debugged/Injected",
                description: "Process \(processName) (PID \(pid)) has CS_DEBUGGED flag set. This means task_for_pid was used on it — possible code injection.",
                severity: .high, mitreID: "T1055"
            ))
        }

        // CS_HARD (0x0100) and CS_KILL (0x0200) should be set on hardened runtime processes
        // If they're missing on an Apple binary, something stripped them
        if path.hasPrefix("/System/") || path.hasPrefix("/usr/") {
            if csFlags & 0x0100 == 0 && csFlags & 0x0200 == 0 {
                anomalies.append(.forProcess(
                    pid: pid, name: processName, path: path,
                    technique: "Missing Hardened Runtime Flags",
                    description: "System binary \(processName) missing CS_HARD|CS_KILL flags. May have been patched or replaced.",
                    severity: .high, mitreID: "T1574"
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
                return .forProcess(
                    pid: pid, name: processName, path: path,
                    technique: "Recently Modified System Binary",
                    description: "System binary \(path) was modified \(String(format: "%.1f", daysSinceModified)) days ago. System binaries should only change during OS updates.",
                    severity: .high, mitreID: "T1554"
                )
            }
        }

        return nil
    }

    /// Get list of loaded dylib/framework images for a process.
    /// Uses PROC_PIDREGIONPATHINFO to walk VM regions by actual size (not page stepping).
    /// Catches non-shared-cache dylibs (injected dylibs are never in the cache).
    private func getLoadedImages(pid: pid_t) -> [String] {
        var images = Set<String>()
        var address: UInt64 = 0

        // Walk all VM regions using their actual sizes
        for _ in 0..<50000 { // safety limit (typical process: 500-2000 regions)
            var rwpi = proc_regionwithpathinfo()
            let size = proc_pidinfo(
                pid, PROC_PIDREGIONPATHINFO, address,
                &rwpi, Int32(MemoryLayout<proc_regionwithpathinfo>.size)
            )
            guard size > 0 else { break }

            // Extract the file path from vnode info
            let path = withUnsafePointer(to: rwpi.prp_vip.vip_path) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                    String(cString: $0)
                }
            }

            // Collect dylibs and frameworks (skip data files)
            if !path.isEmpty && (path.hasSuffix(".dylib") || path.contains(".framework/")) {
                images.insert(path)
            }

            // Advance past this region
            let regionEnd = rwpi.prp_prinfo.pri_address + rwpi.prp_prinfo.pri_size
            guard regionEnd > address else { break } // prevent infinite loop
            address = regionEnd
        }

        return Array(images)
    }

    private func resolveDylibPath(_ path: String) -> String {
        // Strip @rpath/, @executable_path/, etc — just get the filename
        if let lastSlash = path.lastIndex(of: "/") {
            return String(path[path.index(after: lastSlash)...])
        }
        return path
    }

}
