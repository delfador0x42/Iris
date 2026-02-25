import Foundation
import os.log

/// Scans process memory regions via PROC_PIDREGIONPATHINFO + mach_vm_region.
/// Detects anonymous executable regions (shellcode) and suspicious mappings.
///
/// Key advantage over MemoryScanner: For hardened processes where task_for_pid
/// fails, falls back to PROC_PIDREGIONPATHINFO which only needs root access.
/// This catches shellcode in processes that MemoryScanner can't inspect.
public actor XNURegionScanner {
    public static let shared = XNURegionScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "XNURegionScanner")

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        for pid in snapshot.pids {
            guard pid > 0 else { continue }
            let path = snapshot.path(for: pid)
            guard !path.isEmpty else { continue }
            let name = snapshot.name(for: pid)
            anomalies.append(contentsOf: scanRegions(pid: pid, name: name, path: path))
        }
        return anomalies
    }

    /// Scan via task_for_pid → mach_vm_region → PROC_PIDREGIONPATHINFO.
    /// Falls back to PROC_PIDREGIONPATHINFO-only if task_for_pid fails.
    private func scanRegions(pid: pid_t, name: String, path: String) -> [ProcessAnomaly] {
        var task: mach_port_t = 0
        let hasTask = task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS

        defer {
            if hasTask { mach_port_deallocate(mach_task_self_, task) }
        }

        if hasTask {
            return scanWithTaskPort(task: task, pid: pid, name: name, path: path)
        }
        // Fallback: PROC_PIDREGIONPATHINFO without task port
        return scanWithProcPidinfo(pid: pid, name: name, path: path)
    }

    /// Full scan: task port gives us exact region boundaries via mach_vm_region,
    /// then PROC_PIDREGIONPATHINFO gives us the backing file path.
    private func scanWithTaskPort(
        task: mach_port_t, pid: pid_t, name: String, path: String
    ) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        var addr: mach_vm_address_t = 0
        var anonExecRegions: [(addr: UInt64, size: UInt64)] = []

        while true {
            var size: mach_vm_size_t = 0
            var info = vm_region_basic_info_data_64_t()
            var count = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.size / MemoryLayout<Int32>.size)
            var object: mach_port_t = 0

            let kr = withUnsafeMutablePointer(to: &info) { ptr in
                ptr.withMemoryRebound(to: Int32.self, capacity: Int(count)) {
                    mach_vm_region(task, &addr, &size,
                                  VM_REGION_BASIC_INFO_64, $0, &count, &object)
                }
            }
            guard kr == KERN_SUCCESS else { break }

            let isExec = info.protection & VM_PROT_EXECUTE != 0
            if isExec {
                // Check if file-backed via PROC_PIDREGIONPATHINFO
                let regionPath = getRegionPath(pid: pid, addr: addr)
                if regionPath.isEmpty {
                    anonExecRegions.append((addr: UInt64(addr), size: UInt64(size)))
                }
            }

            addr += size
            if addr == 0 { break }
        }

        if !anonExecRegions.isEmpty {
            let totalSize = anonExecRegions.reduce(0) { $0 + $1.size }
            var evidence = [
                "pid: \(pid)", "binary: \(path)",
                "anon_exec_count: \(anonExecRegions.count)",
                "total_anon_exec: \(totalSize / 1024)KB",
                "enum_method: mach_vm_region + PROC_PIDREGIONPATHINFO",
            ]
            for (i, r) in anonExecRegions.prefix(5).enumerated() {
                evidence.append("region_\(i): 0x\(String(r.addr, radix: 16))+\(r.size / 1024)KB")
            }

            let severity: AnomalySeverity = anonExecRegions.count > 3 ? .critical : .high
            anomalies.append(.forProcess(
                pid: pid, name: name, path: path,
                technique: "Anonymous Executable Memory",
                description: "\(name) has \(anonExecRegions.count) anonymous executable region(s) (\(totalSize / 1024)KB). Possible shellcode or reflective injection.",
                severity: severity, mitreID: "T1055.012",
                scannerId: "xnu_regions",
                enumMethod: "mach_vm_region(VM_REGION_BASIC_INFO_64) + PROC_PIDREGIONPATHINFO cross-reference",
                evidence: evidence))
        }

        return anomalies
    }

    /// Fallback: scan known address ranges with PROC_PIDREGIONPATHINFO only.
    /// Less precise (can't enumerate all regions) but works without task port.
    private func scanWithProcPidinfo(pid: pid_t, name: String, path: String) -> [ProcessAnomaly] {
        // Probe the standard macOS user-space range: 0x100000000 - 0x200000000
        // and common anonymous mapping areas
        var probeAddrs: [UInt64] = []
        var a: UInt64 = 0x100000000
        while a < 0x180000000 { probeAddrs.append(a); a += 0x1000000 } // 1MB steps

        var execAnon = 0
        var execTotal = 0
        var firstAnonExec: UInt64 = 0

        for addr in probeAddrs {
            var rpi = proc_regionwithpathinfo()
            let ret = proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, addr,
                                   &rpi, Int32(MemoryLayout<proc_regionwithpathinfo>.size))
            guard ret > 0 else { continue }

            let prot = rpi.prp_prinfo.pri_protection
            let isExec = prot & UInt32(VM_PROT_EXECUTE) != 0
            guard isExec else { continue }
            execTotal += 1

            let regionPath = withUnsafeBytes(of: rpi.prp_vip.vip_path) { buf in
                String(cString: buf.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            if regionPath.isEmpty {
                execAnon += 1
                if firstAnonExec == 0 { firstAnonExec = addr }
            }
        }

        guard execAnon > 0 else { return [] }

        return [.forProcess(
            pid: pid, name: name, path: path,
            technique: "Anonymous Executable Memory (Probe)",
            description: "\(name) has anonymous executable memory at 0x\(String(firstAnonExec, radix: 16)). task_for_pid denied — detected via PROC_PIDREGIONPATHINFO probe.",
            severity: .high, mitreID: "T1055.012",
            scannerId: "xnu_regions",
            enumMethod: "PROC_PIDREGIONPATHINFO probe (no task port)",
            evidence: [
                "pid: \(pid)", "binary: \(path)",
                "anon_exec_found: \(execAnon)",
                "total_exec_probed: \(execTotal)",
                "first_anon_exec: 0x\(String(firstAnonExec, radix: 16))",
                "task_for_pid: denied",
            ])]
    }

    /// Get the file path backing a memory region via PROC_PIDREGIONPATHINFO.
    private func getRegionPath(pid: pid_t, addr: mach_vm_address_t) -> String {
        var rpi = proc_regionwithpathinfo()
        let ret = proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, addr,
                               &rpi, Int32(MemoryLayout<proc_regionwithpathinfo>.size))
        guard ret > 0 else { return "" }
        return withUnsafeBytes(of: rpi.prp_vip.vip_path) { buf in
            String(cString: buf.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
    }
}
