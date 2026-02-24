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
/// 1. Compare on-disk Mach-O header vs in-memory header (64 bytes)
/// 2. Count anonymous executable regions with Mach-O structure (injected code)
///
/// ZERO-TRUST: No process name allowlists. No path-based skips.
/// Every process is checked — a compromised kernel can lie about paths.
public actor ProcessHollowingDetector {
    public static let shared = ProcessHollowingDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "ProcessHollow")

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        for pid in snapshot.pids {
            guard pid > 1 else { continue }
            let name = snapshot.name(for: pid)
            let path = snapshot.path(for: pid)
            if path.isEmpty { continue }

            // Compare disk vs memory Mach-O headers
            if let finding = checkTextSegmentIntegrity(
                pid: pid, name: name, path: path) {
                anomalies.append(finding)
            }

            // Check for anonymous executable regions containing Mach-O structures
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

    /// Check for anonymous executable regions containing Mach-O structures.
    /// Uses VM_REGION_EXTENDED_INFO for proper anonymous detection (share_mode).
    /// JIT code lives in anonymous executable memory but does NOT have Mach-O headers.
    /// Injected code has Mach-O headers in anonymous memory.
    private func checkAnomalousExecutableRegions(
        pid: pid_t, name: String, path: String
    ) -> [ProcessAnomaly] {
        var task: mach_port_t = 0
        guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return [] }
        defer { mach_port_deallocate(mach_task_self_, task) }

        var address: mach_vm_address_t = 0
        var machoAnonCount = 0
        var machoAnonRegions: [String] = []

        while true {
            var size: mach_vm_size_t = 0
            var info = vm_region_extended_info_data_t()
            var infoCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_extended_info_data_t>.size / MemoryLayout<Int32>.size)
            var objectName: mach_port_t = 0
            let kr = withUnsafeMutablePointer(to: &info) { ptr in
                ptr.withMemoryRebound(to: Int32.self, capacity: Int(infoCount)) {
                    mach_vm_region(task, &address, &size,
                                  VM_REGION_EXTENDED_INFO, $0, &infoCount, &objectName)
                }
            }
            guard kr == KERN_SUCCESS else { break }

            let isExec = info.protection & VM_PROT_EXECUTE != 0
            let isAnonymous = info.share_mode == UInt8(SM_PRIVATE)
                || info.share_mode == UInt8(SM_EMPTY)

            // Only flag anonymous executable regions that contain Mach-O structures.
            // JIT code = anonymous + executable but NO Mach-O magic.
            // Injected Mach-O = anonymous + executable + Mach-O magic.
            if isExec && isAnonymous && size > 4096 {
                if hasMachOMagic(task: task, addr: address) {
                    machoAnonCount += 1
                    machoAnonRegions.append(
                        "0x\(String(address, radix: 16))+\(size / 1024)KB")
                }
            }

            address += size
            if address == 0 { break }
        }

        // Any anonymous region with Mach-O structure = injected code
        if machoAnonCount > 0 {
            return [.forProcess(
                pid: pid, name: name, path: path,
                technique: "Mach-O in Anonymous Memory",
                description: "\(name) has \(machoAnonCount) anonymous executable region(s) containing Mach-O headers. Code injection.",
                severity: .critical, mitreID: "T1055.012",
                scannerId: "process_hollowing",
                enumMethod: "mach_vm_region(VM_REGION_EXTENDED_INFO) + magic check",
                evidence: [
                    "pid: \(pid)",
                    "macho_anon_count: \(machoAnonCount)",
                    "regions: \(machoAnonRegions.prefix(5).joined(separator: ", "))",
                ])]
        }
        return []
    }

    /// Check first 4 bytes for Mach-O magic
    private func hasMachOMagic(task: mach_port_t, addr: mach_vm_address_t) -> Bool {
        var magic: UInt32 = 0
        var outSize: mach_vm_size_t = 0
        let kr = withUnsafeMutablePointer(to: &magic) { ptr in
            mach_vm_read_overwrite(
                task, addr, 4,
                mach_vm_address_t(UInt(bitPattern: ptr)), &outSize)
        }
        guard kr == KERN_SUCCESS else { return false }
        return magic == MH_MAGIC_64 || magic == MH_MAGIC
            || magic == FAT_MAGIC || magic == FAT_CIGAM
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

    /// Read Mach-O header from disk, handling FAT/universal binaries.
    /// For FAT binaries: find the arm64 slice and read from that offset.
    /// For thin binaries: read from offset 0.
    private func readDiskMachOHeader(path: String) -> [UInt8]? {
        guard let fh = FileHandle(forReadingAtPath: path) else { return nil }
        defer { fh.closeFile() }
        guard let headerData = try? fh.read(upToCount: 4096), headerData.count >= 64
        else { return nil }

        let magic = headerData.withUnsafeBytes { $0.load(as: UInt32.self) }

        // Thin Mach-O — read directly
        if magic == MH_MAGIC_64 || magic == MH_MAGIC {
            return Array(headerData.prefix(64))
        }

        // FAT/universal binary — find arm64 slice
        let isBE = (magic == FAT_MAGIC)
        let isLE = (magic == FAT_CIGAM)
        guard isBE || isLE else { return nil }

        return headerData.withUnsafeBytes { raw in
            guard raw.count >= 8 else { return nil as [UInt8]? }
            let nArch = isBE
                ? UInt32(bigEndian: raw.load(fromByteOffset: 4, as: UInt32.self))
                : raw.load(fromByteOffset: 4, as: UInt32.self)

            for i in 0..<Int(min(nArch, 8)) {
                let entryOff = 8 + i * MemoryLayout<fat_arch>.size
                guard entryOff + MemoryLayout<fat_arch>.size <= raw.count else { break }
                let arch = raw.load(fromByteOffset: entryOff, as: fat_arch.self)
                let cpuType = isBE ? Int32(bigEndian: arch.cputype) : arch.cputype
                let offset = isBE
                    ? UInt32(bigEndian: arch.offset)
                    : arch.offset

                // CPU_TYPE_ARM64 = 0x0100000C = 16777228
                if cpuType == CPU_TYPE_ARM64 || cpuType == CPU_TYPE_X86_64 {
                    let sliceOff = Int(offset)
                    if sliceOff + 64 <= raw.count {
                        return Array(raw[sliceOff..<(sliceOff + 64)])
                    }
                    // Slice beyond our 4KB read — seek and read
                    fh.seek(toFileOffset: UInt64(sliceOff))
                    if let sliceData = try? fh.read(upToCount: 64), sliceData.count == 64 {
                        return Array(sliceData)
                    }
                }
            }
            return nil as [UInt8]?
        }
    }
}
