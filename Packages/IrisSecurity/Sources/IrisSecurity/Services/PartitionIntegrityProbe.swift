import Foundation
import os.log

/// Reads the raw GPT (GUID Partition Table) directly from /dev/rdisk0 and
/// compares against what IOKit reports about disk partitions.
///
/// Lie detected: "The disk has exactly these partitions and nothing else"
/// Ground truth: Raw GPT bytes from the physical device vs IOKit/diskutil.
///               A firmware implant that adds a hidden partition must either
///               modify both the raw GPT AND the OS-reported data (expensive),
///               or only modify one — creating a detectable contradiction.
///
/// Also verifies GPT CRC32 integrity — if someone modified the partition table
/// without updating the CRC, we catch that too.
///
/// Adversary cost: Must hook both the raw disk read path AND IOKit reporting,
/// or patch the GPT AND update CRCs — requires firmware-level access.
public actor PartitionIntegrityProbe {
    public static let shared = PartitionIntegrityProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "PartitionIntegrity")

    // GPT spec constants
    private let gptSignature: UInt64 = 0x5452415020494645 // "EFI PART"
    private let gptHeaderOffset = 4096 // LBA 1 on 4K-native drives
    private let gptHeaderMinSize = 92

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // Source 1: Raw GPT from disk
        guard let rawGPT = readRawGPT() else {
            logger.warning("Cannot read raw GPT — needs root access to /dev/rdisk0")
            return []
        }

        // Source 2: diskutil list
        let diskutilPartitions = readDiskutilPartitions()

        // Verify GPT header integrity
        if !rawGPT.headerCRCValid {
            anomalies.append(.filesystem(
                name: "GPT Header", path: "/dev/rdisk0",
                technique: "GPT Header CRC Mismatch",
                description: "CRITICAL: GPT header CRC32 does not match. The partition table has been modified without updating the checksum.",
                severity: .critical, mitreID: "T1542",
                scannerId: "partition_integrity",
                enumMethod: "raw /dev/rdisk0 GPT header CRC32 verification",
                evidence: [
                    "stored_crc: \(String(format: "0x%08x", rawGPT.storedHeaderCRC))",
                    "computed_crc: \(String(format: "0x%08x", rawGPT.computedHeaderCRC))",
                ]))
        }

        if !rawGPT.entryCRCValid {
            anomalies.append(.filesystem(
                name: "GPT Entries", path: "/dev/rdisk0",
                technique: "GPT Entry Array CRC Mismatch",
                description: "CRITICAL: GPT partition entry array CRC32 does not match. Partitions may have been added, removed, or modified.",
                severity: .critical, mitreID: "T1542",
                scannerId: "partition_integrity",
                enumMethod: "raw /dev/rdisk0 GPT entry array CRC32 verification",
                evidence: [
                    "stored_crc: \(String(format: "0x%08x", rawGPT.storedEntryCRC))",
                    "computed_crc: \(String(format: "0x%08x", rawGPT.computedEntryCRC))",
                ]))
        }

        // Cross-reference: partition count
        let rawPartitions = rawGPT.partitions.filter { !$0.typeGUID.allSatisfy { $0 == 0 } }
        if rawPartitions.count != diskutilPartitions.count {
            anomalies.append(.filesystem(
                name: "Partition Count", path: "/dev/disk0",
                technique: "Partition Count Mismatch",
                description: "Raw GPT shows \(rawPartitions.count) partitions but diskutil reports \(diskutilPartitions.count). Hidden partition detected.",
                severity: .critical, mitreID: "T1542",
                scannerId: "partition_integrity",
                enumMethod: "raw GPT entry count vs diskutil list partition count",
                evidence: [
                    "raw_gpt_count: \(rawPartitions.count)",
                    "diskutil_count: \(diskutilPartitions.count)",
                ] + rawPartitions.map { "raw: \($0.name) (\($0.startLBA)-\($0.endLBA))" }
                  + diskutilPartitions.map { "diskutil: \($0.identifier) (\($0.size) bytes)" }
            ))
        }

        // Cross-reference: individual partition UUIDs must match
        for rawPart in rawPartitions {
            let rawUUID = rawPart.uniqueGUID
            let match = diskutilPartitions.first { $0.uuid.uppercased() == rawUUID.uppercased() }
            if match == nil {
                anomalies.append(.filesystem(
                    name: rawPart.name, path: "/dev/disk0",
                    technique: "Hidden Partition",
                    description: "Partition '\(rawPart.name)' exists in raw GPT but not reported by diskutil. Possible hidden partition.",
                    severity: .critical, mitreID: "T1542",
                    scannerId: "partition_integrity",
                    enumMethod: "raw GPT unique GUID vs diskutil UUID cross-reference",
                    evidence: [
                        "name: \(rawPart.name)",
                        "uuid: \(rawUUID)",
                        "start_lba: \(rawPart.startLBA)",
                        "end_lba: \(rawPart.endLBA)",
                        "type: \(rawPart.typeGUIDString)",
                    ]))
            }
        }

        logger.info("Partition integrity: \(rawPartitions.count) raw, \(diskutilPartitions.count) diskutil, \(anomalies.count) contradictions")
        return anomalies
    }

    // MARK: - Raw GPT Reading

    private struct RawGPT {
        let headerCRCValid: Bool
        let entryCRCValid: Bool
        let storedHeaderCRC: UInt32
        let computedHeaderCRC: UInt32
        let storedEntryCRC: UInt32
        let computedEntryCRC: UInt32
        let partitions: [RawPartition]
    }

    private struct RawPartition {
        let typeGUID: [UInt8]    // 16 bytes
        let uniqueGUID: String
        let typeGUIDString: String
        let startLBA: UInt64
        let endLBA: UInt64
        let attributes: UInt64
        let name: String
    }

    private func readRawGPT() -> RawGPT? {
        let fd = open("/dev/rdisk0", O_RDONLY)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        // Read GPT header at LBA 1 (offset 4096 for 4K-native)
        var headerBuf = [UInt8](repeating: 0, count: 4096)
        let headerRead = pread(fd, &headerBuf, 4096, off_t(gptHeaderOffset))
        guard headerRead == 4096 else { return nil }

        // Verify signature "EFI PART"
        let sig = headerBuf.withUnsafeBytes { $0.load(as: UInt64.self) }
        guard sig == gptSignature else { return nil }

        // Parse header fields
        let headerSize = headerBuf.withUnsafeBytes { $0.load(fromByteOffset: 12, as: UInt32.self) }
        let storedHeaderCRC = headerBuf.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self) }
        let entryLBA = headerBuf.withUnsafeBytes { $0.load(fromByteOffset: 72, as: UInt64.self) }
        let entryCount = headerBuf.withUnsafeBytes { $0.load(fromByteOffset: 80, as: UInt32.self) }
        let entrySize = headerBuf.withUnsafeBytes { $0.load(fromByteOffset: 84, as: UInt32.self) }
        let storedEntryCRC = headerBuf.withUnsafeBytes { $0.load(fromByteOffset: 88, as: UInt32.self) }

        // Verify header CRC (zero the CRC field, compute over headerSize bytes)
        var headerForCRC = Array(headerBuf.prefix(Int(headerSize)))
        headerForCRC[16] = 0; headerForCRC[17] = 0; headerForCRC[18] = 0; headerForCRC[19] = 0
        let computedHeaderCRC = crc32(headerForCRC)

        // Read partition entries
        let entryArraySize = Int(entryCount) * Int(entrySize)
        var entryBuf = [UInt8](repeating: 0, count: entryArraySize)
        let entryOffset = off_t(entryLBA) * 4096 // 4K-native blocks
        let entryRead = pread(fd, &entryBuf, entryArraySize, entryOffset)
        guard entryRead == entryArraySize else { return nil }

        let computedEntryCRC = crc32(entryBuf)

        // Parse partition entries
        var partitions: [RawPartition] = []
        for i in 0..<Int(entryCount) {
            let base = i * Int(entrySize)
            guard base + 128 <= entryBuf.count else { break }

            let typeGUID = Array(entryBuf[base..<(base + 16)])
            // Skip empty entries
            if typeGUID.allSatisfy({ $0 == 0 }) { continue }

            let uniqueGUID = decodeGUID(Array(entryBuf[(base + 16)..<(base + 32)]))
            let typeGUIDStr = decodeGUID(typeGUID)
            let startLBA = entryBuf.withUnsafeBytes { $0.load(fromByteOffset: base + 32, as: UInt64.self) }
            let endLBA = entryBuf.withUnsafeBytes { $0.load(fromByteOffset: base + 40, as: UInt64.self) }
            let attrs = entryBuf.withUnsafeBytes { $0.load(fromByteOffset: base + 48, as: UInt64.self) }

            // Parse UTF-16LE name (72 bytes max)
            let nameBytes = Array(entryBuf[(base + 56)..<min(base + 128, entryBuf.count)])
            let name = decodeUTF16LE(nameBytes)

            partitions.append(RawPartition(
                typeGUID: typeGUID, uniqueGUID: uniqueGUID, typeGUIDString: typeGUIDStr,
                startLBA: startLBA, endLBA: endLBA, attributes: attrs, name: name))
        }

        return RawGPT(
            headerCRCValid: storedHeaderCRC == computedHeaderCRC,
            entryCRCValid: storedEntryCRC == computedEntryCRC,
            storedHeaderCRC: storedHeaderCRC, computedHeaderCRC: computedHeaderCRC,
            storedEntryCRC: storedEntryCRC, computedEntryCRC: computedEntryCRC,
            partitions: partitions)
    }

    // MARK: - diskutil

    private struct DiskutilPartition {
        let identifier: String
        let uuid: String
        let size: Int64
        let content: String
    }

    private func readDiskutilPartitions() -> [DiskutilPartition] {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/diskutil")
        proc.arguments = ["list", "-plist", "disk0"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        guard (try? proc.run()) != nil else { return [] }
        proc.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let allDisks = plist["AllDisksAndPartitions"] as? [[String: Any]],
              let disk0 = allDisks.first,
              let partitions = disk0["Partitions"] as? [[String: Any]] else { return [] }

        return partitions.compactMap { p in
            guard let id = p["DeviceIdentifier"] as? String,
                  let uuid = p["DiskUUID"] as? String else { return nil }
            let size = p["Size"] as? Int64 ?? 0
            let content = p["Content"] as? String ?? ""
            return DiskutilPartition(identifier: id, uuid: uuid, size: size, content: content)
        }
    }

    // MARK: - GUID Decoding (mixed-endian)

    private func decodeGUID(_ bytes: [UInt8]) -> String {
        guard bytes.count == 16 else { return "invalid" }
        // Mixed-endian: first 3 fields LE, last 2 fields BE
        return String(format: "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                       bytes[3], bytes[2], bytes[1], bytes[0],  // LE uint32
                       bytes[5], bytes[4],                       // LE uint16
                       bytes[7], bytes[6],                       // LE uint16
                       bytes[8], bytes[9],                       // BE
                       bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]) // BE
    }

    private func decodeUTF16LE(_ bytes: [UInt8]) -> String {
        var chars: [UInt16] = []
        for i in stride(from: 0, to: bytes.count - 1, by: 2) {
            let val = UInt16(bytes[i]) | (UInt16(bytes[i + 1]) << 8)
            if val == 0 { break }
            chars.append(val)
        }
        return String(utf16CodeUnits: chars, count: chars.count)
    }

    // MARK: - CRC32

    private func crc32(_ data: [UInt8]) -> UInt32 {
        var crc: UInt32 = 0xFFFFFFFF
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                crc = (crc >> 1) ^ (crc & 1 == 1 ? 0xEDB88320 : 0)
            }
        }
        return crc ^ 0xFFFFFFFF
    }
}
