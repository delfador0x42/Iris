import Foundation
import CryptoKit
import MachO

/// Deep memory analysis: Mach-O magic detection, __TEXT integrity, thread count.
extension MemoryScanner {

    /// Read first 4 bytes of a region and check for Mach-O magic.
    /// Detects reflective loaders that map entire Mach-O binaries into memory.
    func checkMachOMagic(task: mach_port_t, addr: mach_vm_address_t,
                         size: mach_vm_size_t) -> Bool {
        guard size >= 4 else { return false }
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

    /// High thread count may indicate injection (injected threads).
    func checkThreadCount(pid: pid_t, name: String, path: String) -> [ProcessAnomaly] {
        var info = proc_taskinfo()
        let size = proc_pidinfo(pid, PROC_PIDTASKINFO, 0,
                                &info, Int32(MemoryLayout<proc_taskinfo>.size))
        guard size > 0 else { return [] }
        let threads = Int(info.pti_threadnum)
        guard threads > 100 else { return [] }
        return [.forProcess(
            pid: pid, name: name, path: path,
            technique: "Anomalous Thread Count",
            description: "\(name) has \(threads) threads. May indicate injection or mining.",
            severity: .medium, mitreID: "T1055",
            scannerId: "memory",
            enumMethod: "proc_pidinfo(PROC_PIDTASKINFO)",
            evidence: [
                "pid: \(pid)", "thread_count: \(threads)", "threshold: 100",
            ])]
    }
}

/// Compare on-disk binary __TEXT segment with in-memory __TEXT.
/// If they differ, the code was patched in memory (process hollowing).
public enum TextIntegrityChecker {

    /// Check if in-memory __TEXT matches on-disk __TEXT for a process.
    /// Returns anomaly if they differ, nil if they match or can't check.
    public static func check(pid: pid_t, binaryPath: String) -> ProcessAnomaly? {
        guard !binaryPath.isEmpty else { return nil }
        let name = URL(fileURLWithPath: binaryPath).lastPathComponent

        // Read on-disk __TEXT
        guard let diskHash = hashDiskText(path: binaryPath) else { return nil }

        // Read in-memory __TEXT via task_for_pid
        var task: mach_port_t = 0
        guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, task) }

        guard let memHash = hashMemoryText(task: task, path: binaryPath) else { return nil }

        if diskHash != memHash {
            return .forProcess(
                pid: pid, name: name, path: binaryPath,
                technique: "Process Hollowing (__TEXT Modified)",
                description: "\(name) (PID \(pid)) in-memory __TEXT differs from on-disk binary. Code was patched in memory.",
                severity: .critical, mitreID: "T1055.012",
                scannerId: "memory",
                enumMethod: "task_for_pid + mach_vm_read vs disk read, SHA256 compare",
                evidence: [
                    "pid: \(pid)", "disk_hash: \(diskHash.prefix(16))",
                    "mem_hash: \(memHash.prefix(16))", "binary: \(binaryPath)",
                ])
        }
        return nil
    }

    /// SHA256 of __TEXT,__text section from on-disk binary.
    private static func hashDiskText(path: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              data.count > MemoryLayout<mach_header_64>.size else { return nil }
        return data.withUnsafeBytes { buf -> String? in
            guard let base = buf.baseAddress else { return nil }
            let header = base.load(as: mach_header_64.self)
            guard header.magic == MH_MAGIC_64 else { return nil }
            var offset = MemoryLayout<mach_header_64>.size
            for _ in 0..<header.ncmds {
                guard offset + MemoryLayout<load_command>.size <= data.count else { break }
                let lc = base.advanced(by: offset).load(as: load_command.self)
                if lc.cmd == LC_SEGMENT_64 {
                    let seg = base.advanced(by: offset).load(as: segment_command_64.self)
                    let segName = withUnsafeBytes(of: seg.segname) { raw in
                        String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
                    }
                    if segName == "__TEXT" {
                        let textOff = Int(seg.fileoff)
                        let textSize = Int(seg.filesize)
                        guard textOff + textSize <= data.count else { return nil }
                        let slice = data[textOff..<(textOff + textSize)]
                        let h = SHA256.hash(data: slice)
                        return h.map { String(format: "%02x", $0) }.joined()
                    }
                }
                offset += Int(lc.cmdsize)
            }
            return nil
        }
    }

    /// SHA256 of in-memory __TEXT segment for a running process.
    private static func hashMemoryText(task: mach_port_t, path: String) -> String? {
        // Find __TEXT segment info from the on-disk binary
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              data.count > MemoryLayout<mach_header_64>.size else { return nil }
        var textVMAddr: UInt64 = 0
        var textVMSize: UInt64 = 0
        data.withUnsafeBytes { buf in
            guard let base = buf.baseAddress else { return }
            let header = base.load(as: mach_header_64.self)
            guard header.magic == MH_MAGIC_64 else { return }
            var offset = MemoryLayout<mach_header_64>.size
            for _ in 0..<header.ncmds {
                guard offset + MemoryLayout<load_command>.size <= data.count else { break }
                let lc = base.advanced(by: offset).load(as: load_command.self)
                if lc.cmd == LC_SEGMENT_64 {
                    let seg = base.advanced(by: offset).load(as: segment_command_64.self)
                    let segName = withUnsafeBytes(of: seg.segname) { raw in
                        String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
                    }
                    if segName == "__TEXT" {
                        textVMAddr = seg.vmaddr
                        textVMSize = seg.vmsize
                    }
                }
                offset += Int(lc.cmdsize)
            }
        }
        guard textVMSize > 0 else { return nil }

        // Read __TEXT from target process memory
        let readSize = Int(textVMSize)
        let buf = UnsafeMutableRawPointer.allocate(byteCount: readSize, alignment: 8)
        defer { buf.deallocate() }
        var outSize: mach_vm_size_t = 0
        let kr = mach_vm_read_overwrite(
            task, mach_vm_address_t(textVMAddr), mach_vm_size_t(readSize),
            mach_vm_address_t(UInt(bitPattern: buf)), &outSize)
        guard kr == KERN_SUCCESS, outSize > 0 else { return nil }
        let memData = Data(bytes: buf, count: Int(outSize))
        let h = SHA256.hash(data: memData)
        return h.map { String(format: "%02x", $0) }.joined()
    }
}
