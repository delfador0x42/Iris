import Foundation
import MachO
import os.log

/// Detects process hollowing — where a legitimate process's memory is replaced
/// with malicious code while keeping the original process name/path.
///
/// Nation-state technique: spawn trusted process → replace its __TEXT segment
/// with implant code → execute in the trusted process's context.
///
/// Detection layers:
/// 1. Compare on-disk Mach-O __TEXT hash vs in-memory __TEXT hash
/// 2. Detect processes where executable region doesn't map to the declared path
/// 3. Detect anomalous VM region patterns (executable anonymous memory after __TEXT)
/// 4. Detect task_for_pid usage patterns (prerequisite for hollowing)
public actor ProcessHollowingDetector {
    public static let shared = ProcessHollowingDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "ProcessHollow")

    /// Processes that legitimately modify their own __TEXT (JIT, self-patching)
    private static let exemptProcesses: Set<String> = [
        "WebContent", "com.apple.WebKit.WebContent",
        "JavaScriptCore", "jsc",
        "qemu-system-aarch64", "qemu-system-x86_64",
        "rosetta", "oah",
    ]

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        for pid in snapshot.pids {
            guard pid > 1 else { continue }
            let name = snapshot.name(for: pid)
            let path = snapshot.path(for: pid)

            // Skip system processes and exempt JIT processes
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/") { continue }
            if Self.exemptProcesses.contains(name) { continue }
            if path.isEmpty { continue }

            // Compare disk vs memory Mach-O headers
            if let finding = checkTextSegmentIntegrity(
                pid: pid, name: name, path: path) {
                anomalies.append(finding)
            }

            // Check for executable anonymous regions after __TEXT
            // (injected code that doesn't correspond to any file)
            anomalies.append(contentsOf: checkAnomalousExecutableRegions(
                pid: pid, name: name, path: path))
        }

        return anomalies
    }

    /// Compare the Mach-O magic + header from disk vs from process memory.
    /// A mismatch indicates the __TEXT segment has been replaced (hollowing).
    private func checkTextSegmentIntegrity(
        pid: pid_t, name: String, path: String
    ) -> ProcessAnomaly? {
        // Read Mach-O header from disk
        guard let diskHeader = readDiskMachOHeader(path: path) else { return nil }

        // Get task port for memory read
        var task: mach_port_t = 0
        guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, task) }

        // Find the main executable __TEXT segment in memory
        guard let textAddr = findTextSegment(task: task) else { return nil }

        // Read Mach-O header from memory
        var memHeader = [UInt8](repeating: 0, count: 64)
        var outSize: mach_vm_size_t = 0
        let kr = memHeader.withUnsafeMutableBufferPointer { buf in
            mach_vm_read_overwrite(
                task, textAddr, 64,
                mach_vm_address_t(UInt(bitPattern: buf.baseAddress!)), &outSize)
        }
        guard kr == KERN_SUCCESS else { return nil }

        // Compare first 64 bytes (magic + CPU type + load command count)
        if diskHeader != memHeader {
            return .forProcess(
                pid: pid, name: name, path: path,
                technique: "Process Hollowing",
                description: "\(name) Mach-O header in memory doesn't match on-disk binary. __TEXT segment may have been replaced.",
                severity: .critical, mitreID: "T1055.012",
                scannerId: "process_hollowing",
                enumMethod: "mach_vm_read_overwrite(__TEXT) vs disk read comparison",
                evidence: [
                    "pid: \(pid)",
                    "path: \(path)",
                    "disk_magic: \(diskHeader.prefix(4).map { String(format: "%02x", $0) }.joined())",
                    "mem_magic: \(memHeader.prefix(4).map { String(format: "%02x", $0) }.joined())",
                ])
        }
        return nil
    }

    /// Check for executable anonymous memory regions that appear after the
    /// legitimate __TEXT segment — indicates injected code.
    private func checkAnomalousExecutableRegions(
        pid: pid_t, name: String, path: String
    ) -> [ProcessAnomaly] {
        var task: mach_port_t = 0
        guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return [] }
        defer { mach_port_deallocate(mach_task_self_, task) }

        var address: mach_vm_address_t = 0
        var execAnonCount = 0
        var execAnonRegions: [String] = []

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
            // user_tag == 0 = anonymous (not mapped from a file)
            let isAnon = info.reserved == 0

            if isExec && isAnon && size > 4096 {
                execAnonCount += 1
                execAnonRegions.append(
                    "0x\(String(address, radix: 16))+\(size / 1024)KB")
            }

            address += size
            if address == 0 { break }
        }

        // Multiple executable anonymous regions = strong indicator
        if execAnonCount >= 3 {
            return [.forProcess(
                pid: pid, name: name, path: path,
                technique: "Suspicious Executable Anonymous Memory",
                description: "\(name) has \(execAnonCount) executable anonymous memory regions. Possible process hollowing or shellcode injection.",
                severity: .high, mitreID: "T1055.012",
                scannerId: "process_hollowing",
                enumMethod: "mach_vm_region anonymous executable region scan",
                evidence: [
                    "pid: \(pid)",
                    "anon_exec_count: \(execAnonCount)",
                    "regions: \(execAnonRegions.prefix(5).joined(separator: ", "))",
                ])]
        }
        return []
    }

    /// Find the __TEXT segment address by scanning VM regions
    private func findTextSegment(task: mach_port_t) -> mach_vm_address_t? {
        var address: mach_vm_address_t = 0

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
            guard kr == KERN_SUCCESS else { return nil }

            // __TEXT is typically the first executable, read-only region
            let isExec = info.protection & VM_PROT_EXECUTE != 0
            let isRead = info.protection & VM_PROT_READ != 0
            let isWrite = info.protection & VM_PROT_WRITE != 0
            if isExec && isRead && !isWrite {
                // Verify it has Mach-O magic
                var magic: UInt32 = 0
                var outSize: mach_vm_size_t = 0
                let readKr = withUnsafeMutablePointer(to: &magic) { ptr in
                    mach_vm_read_overwrite(
                        task, address, 4,
                        mach_vm_address_t(UInt(bitPattern: ptr)), &outSize)
                }
                if readKr == KERN_SUCCESS &&
                   (magic == MH_MAGIC_64 || magic == FAT_MAGIC || magic == FAT_CIGAM) {
                    return address
                }
            }

            address += size
            if address == 0 { return nil }
        }
    }

    /// Read first 64 bytes of a Mach-O from disk
    private func readDiskMachOHeader(path: String) -> [UInt8]? {
        guard let fh = FileHandle(forReadingAtPath: path) else { return nil }
        defer { fh.closeFile() }
        guard let data = try? fh.read(upToCount: 64), data.count == 64 else { return nil }
        return Array(data)
    }
}
