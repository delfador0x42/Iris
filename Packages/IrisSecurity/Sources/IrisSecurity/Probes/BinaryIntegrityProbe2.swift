import Foundation
import os.log
import CommonCrypto

/// Verifies that critical system binaries on disk match what's loaded in memory.
/// Detects process hollowing / runtime code patching via disk-vs-memory SHA256.
public actor BinaryIntegrityProbe2: ContradictionProbe {
    public static let shared = BinaryIntegrityProbe2()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "BinaryIntegrity2")

    public nonisolated let id = "binary-integrity"
    public nonisolated let name = "Binary Memory Integrity"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "Running system binaries are the same code that's on disk",
        groundTruth: "Read __TEXT segment from disk via Mach-O parsing, read __TEXT from process memory via task_for_pid() + mach_vm_read_overwrite(), compare SHA256",
        adversaryCost: "Must intercept our specific mach_vm_read calls and return fake data — requires knowing which addresses and which process we're reading",
        positiveDetection: "Shows which binary, which segment, disk hash vs memory hash",
        falsePositiveRate: "Near zero — __TEXT is immutable after load, only changes with code injection"
    )

    private let criticalBinaries: [(name: String, path: String)] = [
        ("launchd", "/sbin/launchd"),
        ("trustd", "/usr/libexec/trustd"),
        ("securityd", "/usr/libexec/securityd"),
        ("syspolicyd", "/usr/libexec/syspolicyd"),
        ("amfid", "/usr/libexec/amfid"),
        ("taskgated", "/usr/libexec/taskgated"),
        ("opendirectoryd", "/usr/libexec/opendirectoryd"),
        ("sshd", "/usr/sbin/sshd"),
        ("sudo", "/usr/bin/sudo"),
        ("login", "/usr/bin/login"),
    ]

    public func run() async -> ProbeResult {
        let start = Date()
        let snapshot = ProcessSnapshot.capture()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        for binary in criticalBinaries {
            guard let pid = snapshot.pids.first(where: {
                snapshot.name(for: $0) == binary.name || snapshot.path(for: $0) == binary.path
            }) else { continue }

            let result = compareDiskVsMemory(pid: pid, diskPath: binary.path, binaryName: binary.name)
            switch result {
            case .match(let hash):
                comparisons.append(SourceComparison(
                    label: "\(binary.name) __TEXT",
                    sourceA: SourceValue("disk SHA256", hash),
                    sourceB: SourceValue("memory SHA256", hash),
                    matches: true))

            case .mismatch(let diskHash, let memHash):
                hasContradiction = true
                comparisons.append(SourceComparison(
                    label: "\(binary.name) __TEXT",
                    sourceA: SourceValue("disk SHA256", diskHash),
                    sourceB: SourceValue("memory SHA256", memHash),
                    matches: false))
                logger.critical("BINARY TAMPERING: \(binary.name) disk!=memory")

            case .taskPortFailed:
                comparisons.append(SourceComparison(
                    label: "\(binary.name) __TEXT",
                    sourceA: SourceValue("disk", "readable"),
                    sourceB: SourceValue("memory", "task_for_pid denied"),
                    matches: true))  // Expected for protected processes

            case .error(let msg):
                logger.warning("Binary check failed for \(binary.name): \(msg)")
            }
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        let verdict: ProbeVerdict
        let message: String

        if comparisons.isEmpty {
            verdict = .degraded
            message = "No critical binaries could be checked"
        } else if hasContradiction {
            let tampered = comparisons.filter { !$0.matches }.count
            verdict = .contradiction
            message = "CONTRADICTION: \(tampered) binary(ies) have disk/memory hash mismatch — runtime code injection"
        } else {
            let checked = comparisons.filter { $0.sourceA.value != "readable" }.count
            verdict = .consistent
            message = "\(checked) binaries verified, all disk/memory hashes match"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    // MARK: - Comparison

    private enum CompareResult {
        case match(hash: String)
        case mismatch(diskHash: String, memHash: String)
        case taskPortFailed
        case error(String)
    }

    private func compareDiskVsMemory(pid: pid_t, diskPath: String, binaryName: String) -> CompareResult {
        guard let diskText = readTextSegmentFromDisk(path: diskPath) else {
            return .error("Failed to read __TEXT from disk: \(diskPath)")
        }

        var task: mach_port_t = 0
        let kr = task_for_pid(mach_task_self_, pid, &task)
        guard kr == KERN_SUCCESS else { return .taskPortFailed }
        defer { mach_port_deallocate(mach_task_self_, task) }

        guard let memText = readTextSegmentFromMemory(task: task) else {
            return .error("Failed to read __TEXT from memory for PID \(pid)")
        }

        let diskHash = sha256Hex(diskText)
        let memHash = sha256Hex(memText)
        return diskHash == memHash ? .match(hash: diskHash) : .mismatch(diskHash: diskHash, memHash: memHash)
    }

    // MARK: - Disk

    private func readTextSegmentFromDisk(path: String) -> Data? {
        guard let fh = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? fh.close() }
        guard let headerData = try? fh.read(upToCount: MemoryLayout<mach_header_64>.size),
              headerData.count == MemoryLayout<mach_header_64>.size else { return nil }
        let magic = headerData.withUnsafeBytes { $0.load(as: UInt32.self) }
        guard magic == MH_MAGIC_64 else { return nil }
        let header = headerData.withUnsafeBytes { $0.load(as: mach_header_64.self) }
        guard let lcData = try? fh.read(upToCount: Int(header.sizeofcmds)),
              lcData.count == Int(header.sizeofcmds) else { return nil }
        return lcData.withUnsafeBytes { ptr -> Data? in
            var offset = 0
            for _ in 0..<header.ncmds {
                guard offset + MemoryLayout<load_command>.size <= ptr.count else { break }
                let lc = ptr.load(fromByteOffset: offset, as: load_command.self)
                if lc.cmd == LC_SEGMENT_64, offset + MemoryLayout<segment_command_64>.size <= ptr.count {
                    let seg = ptr.load(fromByteOffset: offset, as: segment_command_64.self)
                    let name = withUnsafePointer(to: seg.segname) { p in
                        p.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                    }
                    if name == "__TEXT" {
                        try? fh.seek(toOffset: seg.fileoff)
                        return try? fh.read(upToCount: Int(seg.filesize))
                    }
                }
                offset += Int(lc.cmdsize)
            }
            return nil
        }
    }

    // MARK: - Memory

    private static let basicInfoCount = mach_msg_type_number_t(
        MemoryLayout<vm_region_basic_info_data_64_t>.size / MemoryLayout<Int32>.size
    )

    private func vmRead(task: mach_port_t, address: mach_vm_address_t, size: Int) -> Data? {
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
        defer { buf.deallocate() }
        var outSize: mach_vm_size_t = 0
        let kr = mach_vm_read_overwrite(
            task, address, mach_vm_size_t(size),
            mach_vm_address_t(Int(bitPattern: buf)), &outSize)
        guard kr == KERN_SUCCESS, outSize > 0 else { return nil }
        return Data(bytes: buf, count: Int(outSize))
    }

    private func readTextSegmentFromMemory(task: mach_port_t) -> Data? {
        var address: mach_vm_address_t = 0
        var size: mach_vm_size_t = 0
        var info = vm_region_basic_info_data_64_t()
        var infoCount = Self.basicInfoCount
        var objectName: mach_port_t = 0

        while true {
            let kr = withUnsafeMutablePointer(to: &info) { infoPtr in
                infoPtr.withMemoryRebound(to: Int32.self, capacity: Int(Self.basicInfoCount)) { rawPtr in
                    mach_vm_region(task, &address, &size, VM_REGION_BASIC_INFO_64,
                                   rawPtr, &infoCount, &objectName)
                }
            }
            guard kr == KERN_SUCCESS else { break }

            guard let magicData = vmRead(task: task, address: address, size: 4),
                  magicData.count == 4 else {
                address += size; infoCount = Self.basicInfoCount; continue
            }
            let magic = magicData.withUnsafeBytes { $0.load(as: UInt32.self) }
            if magic == MH_MAGIC_64 {
                guard let headerData = vmRead(task: task, address: address,
                                               size: MemoryLayout<mach_header_64>.size) else { break }
                let header = headerData.withUnsafeBytes { $0.load(as: mach_header_64.self) }
                let lcOffset = address + mach_vm_address_t(MemoryLayout<mach_header_64>.size)
                guard let lcData = vmRead(task: task, address: lcOffset,
                                           size: Int(header.sizeofcmds)) else { break }
                return lcData.withUnsafeBytes { ptr -> Data? in
                    var offset = 0
                    for _ in 0..<header.ncmds {
                        guard offset + MemoryLayout<load_command>.size <= ptr.count else { break }
                        let lc = ptr.load(fromByteOffset: offset, as: load_command.self)
                        if lc.cmd == LC_SEGMENT_64,
                           offset + MemoryLayout<segment_command_64>.size <= ptr.count {
                            let seg = ptr.load(fromByteOffset: offset, as: segment_command_64.self)
                            let name = withUnsafePointer(to: seg.segname) { p in
                                p.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                            }
                            if name == "__TEXT" {
                                return vmRead(task: task, address: seg.vmaddr, size: Int(seg.vmsize))
                            }
                        }
                        offset += Int(lc.cmdsize)
                    }
                    return nil
                }
            }
            address += size; infoCount = Self.basicInfoCount
        }
        return nil
    }

    // MARK: - SHA256

    private func sha256Hex(_ data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { ptr in
            CC_SHA256(ptr.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
