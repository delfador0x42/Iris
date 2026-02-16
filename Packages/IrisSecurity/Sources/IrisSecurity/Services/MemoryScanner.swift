import Foundation
import os.log
import CryptoKit

/// Scans process memory via native Mach APIs (no shell-outs).
/// Three detection layers:
/// 1. RWX regions via mach_vm_region (shellcode, JIT abuse)
/// 2. Mach-O headers in anonymous regions (reflective loading)
/// 3. Thread count anomalies (injected threads)
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
            guard pid > 0 else { continue }
            let name = snapshot.name(for: pid)
            let path = snapshot.path(for: pid)
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/") { continue }
            anomalies.append(contentsOf: scanMemoryRegions(pid: pid, name: name, path: path))
            anomalies.append(contentsOf: checkThreadCount(pid: pid, name: name, path: path))
        }
        return anomalies
    }

    /// Walk VM regions via mach_vm_region — detect RWX + Mach-O in anonymous memory.
    private func scanMemoryRegions(pid: pid_t, name: String, path: String) -> [ProcessAnomaly] {
        if jitProcesses.contains(name) { return [] }
        var task: mach_port_t = 0
        guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return [] }
        defer { mach_port_deallocate(mach_task_self_, task) }

        var address: mach_vm_address_t = 0
        var rwxCount = 0
        var machoInAnon = false
        var anomalies: [ProcessAnomaly] = []

        while true {
            var size: mach_vm_size_t = 0
            var info = vm_region_basic_info_data_64_t()
            var infoCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.size / MemoryLayout<Int32>.size)
            var objectName: mach_port_t = 0
            let kr = withUnsafeMutablePointer(to: &info) { ptr in
                ptr.withMemoryRebound(to: Int32.self, capacity: Int(infoCount)) {
                    mach_vm_region(task, &address, &size,
                                  VM_REGION_BASIC_INFO_64, $0, &infoCount, &objectName)
                }
            }
            guard kr == KERN_SUCCESS else { break }

            let isExec = info.protection & VM_PROT_EXECUTE != 0
            let isWrite = info.protection & VM_PROT_WRITE != 0
            let maxExec = info.max_protection & VM_PROT_EXECUTE != 0
            let maxWrite = info.max_protection & VM_PROT_WRITE != 0

            // RWX: current protection has both write and execute
            if isExec && isWrite { rwxCount += 1 }
            // Max RWX: region can be made writable+executable (potential JIT abuse)
            else if isExec && maxWrite && maxExec { rwxCount += 1 }

            // Check for Mach-O magic in executable anonymous regions
            if isExec && !machoInAnon {
                machoInAnon = checkMachOMagic(task: task, addr: address, size: size)
            }

            address += size
            if address == 0 { break }
        }

        if rwxCount > 0 {
            anomalies.append(.forProcess(
                pid: pid, name: name, path: path,
                technique: "RWX Memory Regions",
                description: "\(name) has \(rwxCount) RWX region(s). Potential shellcode.",
                severity: .high, mitreID: "T1055.012",
                scannerId: "memory",
                enumMethod: "mach_vm_region(VM_REGION_BASIC_INFO_64)",
                evidence: [
                    "pid: \(pid)", "rwx_count: \(rwxCount)", "process: \(name)",
                ]))
        }

        if machoInAnon {
            anomalies.append(.forProcess(
                pid: pid, name: name, path: path,
                technique: "Reflective Code Loading",
                description: "\(name) has Mach-O headers in anonymous executable memory. Possible reflective injection.",
                severity: .critical, mitreID: "T1620",
                scannerId: "memory",
                enumMethod: "mach_vm_region + mach_vm_read_overwrite (magic check)",
                evidence: [
                    "pid: \(pid)", "macho_magic: detected in anonymous region",
                    "process: \(name)",
                ]))
        }
        return anomalies
    }
}
