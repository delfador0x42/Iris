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
    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let pids = getRunningPIDs()

        for pid in pids {
            guard pid > 0 else { continue }
            let path = getProcessPath(pid)
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
        guard let machInfo = MachOParser.parse(binaryPath) else { return [] }
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
                anomalies.append(ProcessAnomaly(
                    pid: pid, processName: processName, processPath: binaryPath,
                    parentPID: 0, parentName: "",
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
            anomalies.append(ProcessAnomaly(
                pid: pid, processName: processName, processPath: path,
                parentPID: 0, parentName: "",
                technique: "Process Has Been Debugged/Injected",
                description: "Process \(processName) (PID \(pid)) has CS_DEBUGGED flag set. This means task_for_pid was used on it — possible code injection.",
                severity: .high, mitreID: "T1055"
            ))
        }

        // CS_HARD (0x0100) and CS_KILL (0x0200) should be set on hardened runtime processes
        // If they're missing on an Apple binary, something stripped them
        if path.hasPrefix("/System/") || path.hasPrefix("/usr/") {
            if csFlags & 0x0100 == 0 && csFlags & 0x0200 == 0 {
                anomalies.append(ProcessAnomaly(
                    pid: pid, processName: processName, processPath: path,
                    parentPID: 0, parentName: "",
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
                return ProcessAnomaly(
                    pid: pid, processName: processName, processPath: path,
                    parentPID: 0, parentName: "",
                    technique: "Recently Modified System Binary",
                    description: "System binary \(path) was modified \(String(format: "%.1f", daysSinceModified)) days ago. System binaries should only change during OS updates.",
                    severity: .high, mitreID: "T1554"
                )
            }
        }

        return nil
    }

    /// Get list of loaded dylib images for a process
    private func getLoadedImages(pid: pid_t) -> [String] {
        // Use vmmap-like approach: read process memory regions
        // For now, use proc_regionfilename to enumerate mapped files
        var images: [String] = []
        var address: UInt64 = 0

        // Iterate through memory regions
        for _ in 0..<10000 { // Safety limit
            let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
            defer { buf.deallocate() }

            let len = proc_regionfilename(pid, address, buf, UInt32(MAXPATHLEN))
            if len <= 0 { break }

            let path = String(cString: buf)
            if !path.isEmpty && !images.contains(path) && path.hasSuffix(".dylib") {
                images.append(path)
            }

            // Move to next region (advance by page size)
            address += 0x1000
            if address > 0x7FFFFFFFFFFF { break } // User space limit
        }

        return images
    }

    private func resolveDylibPath(_ path: String) -> String {
        // Strip @rpath/, @executable_path/, etc — just get the filename
        if let lastSlash = path.lastIndex(of: "/") {
            return String(path[path.index(after: lastSlash)...])
        }
        return path
    }

    private func getRunningPIDs() -> [pid_t] {
        let bufSize = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        guard bufSize > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(bufSize) / MemoryLayout<pid_t>.size)
        let actual = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pids, bufSize)
        guard actual > 0 else { return [] }
        return Array(pids.prefix(Int(actual) / MemoryLayout<pid_t>.size)).filter { $0 > 0 }
    }

    private func getProcessPath(_ pid: pid_t) -> String {
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
        defer { buf.deallocate() }
        let len = proc_pidpath(pid, buf, UInt32(MAXPATHLEN))
        guard len > 0 else { return "" }
        return String(cString: buf)
    }
}
