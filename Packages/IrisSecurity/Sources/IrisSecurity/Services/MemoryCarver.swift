import Foundation
import CryptoKit
import os.log

/// Carves executable memory regions from a process for analysis.
/// Uses task_for_pid + mach_vm_region + mach_vm_read to extract
/// code pages from suspicious processes (fileless, hidden, injected).
public enum MemoryCarver {
    private static let logger = Logger(subsystem: "com.wudan.iris", category: "MemoryCarver")

    /// Result of carving a process's executable memory.
    public struct CarvedBinary: Sendable {
        public let pid: pid_t
        public let regions: Int
        public let totalBytes: Int
        public let sha256: String
        public let tempPath: String
    }

    /// Carve all executable memory regions from a process into a single file.
    /// Returns nil if task_for_pid fails or no executable regions found.
    public static func carve(pid: pid_t) -> CarvedBinary? {
        var task: mach_port_t = 0
        guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else {
            logger.warning("task_for_pid failed for PID \(pid)")
            return nil
        }
        defer { mach_port_deallocate(mach_task_self_, task) }

        var address: mach_vm_address_t = 0
        var totalBytes = 0
        var regionCount = 0
        var allData = Data()

        // Walk all VM regions
        while true {
            var size: mach_vm_size_t = 0
            var info = vm_region_basic_info_data_64_t()
            var infoCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.size / MemoryLayout<Int32>.size
            )
            var objectName: mach_port_t = 0

            let kr = withUnsafeMutablePointer(to: &info) { ptr in
                ptr.withMemoryRebound(to: Int32.self, capacity: Int(infoCount)) { intPtr in
                    mach_vm_region(task, &address, &size,
                                  VM_REGION_BASIC_INFO_64,
                                  intPtr, &infoCount, &objectName)
                }
            }
            guard kr == KERN_SUCCESS else { break }

            // Only carve executable regions (code pages)
            if info.protection & VM_PROT_EXECUTE != 0 {
                let regionSize = Int(size)
                // Cap per-region read at 16MB to avoid memory issues
                let readSize = min(regionSize, 16 * 1024 * 1024)
                var outSize: mach_vm_size_t = 0
                let buf = UnsafeMutableRawPointer.allocate(byteCount: readSize, alignment: 8)
                defer { buf.deallocate() }

                let readKr = mach_vm_read_overwrite(
                    task, address, mach_vm_size_t(readSize),
                    mach_vm_address_t(UInt(bitPattern: buf)), &outSize
                )
                if readKr == KERN_SUCCESS && outSize > 0 {
                    allData.append(Data(bytes: buf, count: Int(outSize)))
                    totalBytes += Int(outSize)
                    regionCount += 1
                }
            }

            address += size
            if address == 0 { break } // wrapped around
        }

        guard !allData.isEmpty else {
            logger.info("No executable regions found for PID \(pid)")
            return nil
        }

        // Write to temp file
        let hash = SHA256.hash(data: allData)
        let sha256 = hash.map { String(format: "%02x", $0) }.joined()
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("iris_carved")
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let tempPath = tempDir.appendingPathComponent("\(pid)_\(sha256.prefix(16)).bin").path

        guard FileManager.default.createFile(atPath: tempPath, contents: allData) else {
            logger.error("Failed to write carved binary to \(tempPath)")
            return nil
        }

        logger.info("Carved PID \(pid): \(regionCount) regions, \(totalBytes) bytes → \(tempPath)")
        return CarvedBinary(
            pid: pid, regions: regionCount,
            totalBytes: totalBytes, sha256: sha256, tempPath: tempPath
        )
    }

    /// Carve and check with VirusTotal in one step.
    public static func carveAndCheck(pid: pid_t) async -> (CarvedBinary, VTVerdict?)? {
        guard let carved = carve(pid: pid) else { return nil }
        // Check hash first (no upload of memory dumps by default)
        let verdict = await VirusTotalService.shared.checkHash(carved.sha256)
        return (carved, verdict)
    }

    /// Clean up old carved files (older than 1 hour).
    public static func cleanup() {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("iris_carved")
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: tempDir.path) else {
            return
        }
        let cutoff = Date().addingTimeInterval(-3600)
        for file in files {
            let path = tempDir.appendingPathComponent(file).path
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                  let created = attrs[.creationDate] as? Date,
                  created < cutoff else { continue }
            try? FileManager.default.removeItem(atPath: path)
        }
    }
}
