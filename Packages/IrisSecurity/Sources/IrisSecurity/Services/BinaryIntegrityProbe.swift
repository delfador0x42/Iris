import Foundation
import os.log

/// Verifies that system binaries on disk match what's loaded in memory.
///
/// Lie detected: "This binary is the original Apple code"
/// Ground truth: Read __TEXT segment from disk, read __TEXT from process memory
///               via task_for_pid() + mach_vm_read_overwrite(). Compare hashes.
///
/// If they differ, the running binary has been patched in memory — classic
/// code injection / process hollowing that survives no file-on-disk.
///
/// Adversary cost: Would need to intercept our specific mach_vm_read calls
/// and return fake data — requires knowing which addresses we're reading.
public actor BinaryIntegrityProbe {
    public static let shared = BinaryIntegrityProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "BinaryIntegrity")

    /// Critical system binaries to verify. These are high-value targets
    /// for nation-state actors because compromising them gives persistence + stealth.
    private let criticalBinaries: [(name: String, path: String)] = [
        ("launchd", "/sbin/launchd"),
        ("trustd", "/usr/libexec/trustd"),
        ("securityd", "/usr/libexec/securityd"),
        ("syspolicyd", "/usr/libexec/syspolicyd"),
        ("amfid", "/usr/libexec/amfid"),
        ("taskgated", "/usr/libexec/taskgated"),
        ("opendirectoryd", "/usr/libexec/opendirectoryd"),
        ("diskarbitrationd", "/usr/libexec/diskarbitrationd"),
        ("configd", "/usr/libexec/configd"),
        ("mDNSResponder", "/usr/sbin/mDNSResponder"),
        ("sshd", "/usr/sbin/sshd"),
        ("sudo", "/usr/bin/sudo"),
        ("login", "/usr/bin/login"),
        ("su", "/usr/bin/su"),
    ]

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        for binary in criticalBinaries {
            // Find running instance of this binary by matching name or path
            guard let pid = snapshot.pids.first(where: {
                snapshot.name(for: $0) == binary.name || snapshot.path(for: $0) == binary.path
            }) else { continue }

            let result = compareDiskVsMemory(pid: pid, diskPath: binary.path)

            switch result {
            case .match:
                break // Clean — disk matches memory

            case .mismatch(let diskHash, let memHash, let segmentName):
                anomalies.append(.forProcess(
                    pid: pid, name: binary.name, path: binary.path,
                    technique: "Binary Memory Tampering",
                    description: "CRITICAL: \(binary.name) \(segmentName) on disk does NOT match memory. Runtime code injection detected.",
                    severity: .critical, mitreID: "T1055.012",
                    scannerId: "binary_integrity_probe",
                    enumMethod: "task_for_pid() + mach_vm_read_overwrite() vs disk SHA256",
                    evidence: [
                        "pid: \(pid)",
                        "path: \(binary.path)",
                        "segment: \(segmentName)",
                        "disk_sha256: \(diskHash)",
                        "memory_sha256: \(memHash)",
                    ]))
                logger.critical("BINARY TAMPERING: \(binary.name) disk!=memory segment=\(segmentName)")

            case .taskPortFailed:
                logger.debug("task_for_pid failed for \(binary.name) (PID \(pid)) — expected for protected processes")

            case .error(let msg):
                logger.warning("Binary integrity check failed for \(binary.name): \(msg)")
            }
        }

        return anomalies
    }

    // MARK: - Comparison Engine

    private enum CompareResult {
        case match
        case mismatch(diskHash: String, memHash: String, segment: String)
        case taskPortFailed
        case error(String)
    }

    private func compareDiskVsMemory(pid: pid_t, diskPath: String) -> CompareResult {
        // Step 1: Read __TEXT segment from disk
        guard let diskTextData = readTextSegmentFromDisk(path: diskPath) else {
            return .error("Failed to read __TEXT from disk: \(diskPath)")
        }

        // Step 2: Get task port
        var task: mach_port_t = 0
        let kr = task_for_pid(mach_task_self_, pid, &task)
        guard kr == KERN_SUCCESS else {
            return .taskPortFailed
        }
        defer { mach_port_deallocate(mach_task_self_, task) }

        // Step 3: Find and read __TEXT segment from memory
        guard let memTextData = readTextSegmentFromMemory(task: task) else {
            return .error("Failed to read __TEXT from memory for PID \(pid)")
        }

        // Step 4: Compare
        let diskHash = sha256Hex(diskTextData)
        let memHash = sha256Hex(memTextData)

        if diskHash == memHash {
            return .match
        } else {
            return .mismatch(diskHash: diskHash, memHash: memHash, segment: "__TEXT")
        }
    }

    // MARK: - Disk Reading

    private func readTextSegmentFromDisk(path: String) -> Data? {
        guard let fh = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? fh.close() }

        // Read Mach-O header
        guard let headerData = try? fh.read(upToCount: MemoryLayout<mach_header_64>.size),
              headerData.count == MemoryLayout<mach_header_64>.size else { return nil }

        let magic = headerData.withUnsafeBytes { $0.load(as: UInt32.self) }
        guard magic == MH_MAGIC_64 else { return nil }

        let header = headerData.withUnsafeBytes { $0.load(as: mach_header_64.self) }

        // Read load commands
        guard let lcData = try? fh.read(upToCount: Int(header.sizeofcmds)),
              lcData.count == Int(header.sizeofcmds) else { return nil }

        // Find __TEXT segment
        return lcData.withUnsafeBytes { ptr -> Data? in
            var offset = 0
            for _ in 0..<header.ncmds {
                guard offset + MemoryLayout<load_command>.size <= ptr.count else { break }
                let lc = ptr.load(fromByteOffset: offset, as: load_command.self)

                if lc.cmd == LC_SEGMENT_64, offset + MemoryLayout<segment_command_64>.size <= ptr.count {
                    let seg = ptr.load(fromByteOffset: offset, as: segment_command_64.self)
                    let name = withUnsafePointer(to: seg.segname) { namePtr in
                        namePtr.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                    }
                    if name == "__TEXT" {
                        // Read the actual segment data from disk
                        try? fh.seek(toOffset: seg.fileoff)
                        return try? fh.read(upToCount: Int(seg.filesize))
                    }
                }
                offset += Int(lc.cmdsize)
            }
            return nil
        }
    }

    // MARK: - Memory Reading

    /// VM_REGION_BASIC_INFO_COUNT_64 is a C macro; compute it in Swift.
    private static let basicInfoCount = mach_msg_type_number_t(
        MemoryLayout<vm_region_basic_info_data_64_t>.size / MemoryLayout<Int32>.size
    )

    /// Read a block of memory from a remote task into a local Data buffer.
    private func vmRead(task: mach_port_t, address: mach_vm_address_t, size: Int) -> Data? {
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
        defer { buf.deallocate() }
        var outSize: mach_vm_size_t = 0
        let kr = mach_vm_read_overwrite(
            task, address, mach_vm_size_t(size),
            mach_vm_address_t(Int(bitPattern: buf)), &outSize
        )
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

            // Check for Mach-O 64-bit magic at this address
            guard let magicData = vmRead(task: task, address: address, size: 4),
                  magicData.count == 4 else {
                address += size
                infoCount = Self.basicInfoCount
                continue
            }

            let magic = magicData.withUnsafeBytes { $0.load(as: UInt32.self) }
            if magic == MH_MAGIC_64 {
                // Read full header
                guard let headerData = vmRead(task: task, address: address,
                                               size: MemoryLayout<mach_header_64>.size) else { break }
                let header = headerData.withUnsafeBytes { $0.load(as: mach_header_64.self) }

                // Read load commands
                let lcOffset = address + mach_vm_address_t(MemoryLayout<mach_header_64>.size)
                guard let lcData = vmRead(task: task, address: lcOffset,
                                           size: Int(header.sizeofcmds)) else { break }

                // Find __TEXT segment
                return lcData.withUnsafeBytes { ptr -> Data? in
                    var offset = 0
                    for _ in 0..<header.ncmds {
                        guard offset + MemoryLayout<load_command>.size <= ptr.count else { break }
                        let lc = ptr.load(fromByteOffset: offset, as: load_command.self)

                        if lc.cmd == LC_SEGMENT_64,
                           offset + MemoryLayout<segment_command_64>.size <= ptr.count {
                            let seg = ptr.load(fromByteOffset: offset, as: segment_command_64.self)
                            let name = withUnsafePointer(to: seg.segname) { namePtr in
                                namePtr.withMemoryRebound(to: CChar.self, capacity: 16) {
                                    String(cString: $0)
                                }
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

            address += size
            infoCount = Self.basicInfoCount
        }
        return nil
    }

    // MARK: - SHA256

    private func sha256Hex(_ data: Data) -> String {
        // Use CommonCrypto-free implementation via the Rust FFI if available,
        // or fall back to simple hash for comparison purposes
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { ptr in
            // CC_SHA256 is available via CommonCrypto
            CC_SHA256(ptr.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}

import CommonCrypto
