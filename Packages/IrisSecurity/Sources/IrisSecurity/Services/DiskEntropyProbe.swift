import Foundation
import os.log

/// Scans raw disk regions between and beyond known partitions for hidden data.
///
/// Lie detected: "There's nothing between the partitions"
/// Ground truth: Read raw blocks from the gaps between GPT partitions.
///               Unallocated space should be all-zeros (or near-zero entropy).
///               High entropy (>7.5 bits/byte) in unallocated space indicates
///               encrypted hidden data — a firmware implant storage area.
///
/// Also checks: Blocks beyond the last partition and before the backup GPT.
///
/// Adversary cost: Would need to either not store data on disk (pure memory implant)
/// or encrypt it in-place AND make raw reads return zeros — requires firmware hooks.
public actor DiskEntropyProbe {
    public static let shared = DiskEntropyProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "DiskEntropy")

    private let blockSize = 4096
    private let samplesPerGap = 8 // Read 8 blocks per gap region
    private let entropyThreshold: Double = 7.0 // bits/byte (max is 8.0 for random)

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // Get partition boundaries from raw GPT
        guard let partitions = readPartitionBoundaries() else {
            logger.warning("Cannot read partition boundaries — needs root")
            return []
        }
        guard let totalLBAs = readDiskTotalLBAs() else { return [] }

        let fd = open("/dev/rdisk0", O_RDONLY)
        guard fd >= 0 else { return [] }
        defer { close(fd) }

        // Find gaps between partitions
        let sorted = partitions.sorted { $0.startLBA < $1.startLBA }
        var gaps: [(start: UInt64, end: UInt64, description: String)] = []

        // Gap before first partition (after GPT entries, LBA 34 typically)
        let gptEnd: UInt64 = 34 // Standard GPT overhead
        if let first = sorted.first, first.startLBA > gptEnd + 1 {
            gaps.append((gptEnd, first.startLBA - 1, "before first partition"))
        }

        // Gaps between partitions
        for i in 0..<(sorted.count - 1) {
            let gapStart = sorted[i].endLBA + 1
            let gapEnd = sorted[i + 1].startLBA - 1
            if gapEnd > gapStart + 1 {
                gaps.append((gapStart, gapEnd, "between '\(sorted[i].name)' and '\(sorted[i + 1].name)'"))
            }
        }

        // Gap after last partition (before backup GPT at last LBA)
        if let last = sorted.last, last.endLBA + 2 < totalLBAs {
            gaps.append((last.endLBA + 1, totalLBAs - 34, "after last partition"))
        }

        // Sample each gap
        for gap in gaps {
            let gapSize = gap.end - gap.start + 1
            guard gapSize > 0 else { continue }

            let step = max(1, gapSize / UInt64(samplesPerGap))
            var highEntropyBlocks = 0
            var totalSampled = 0
            var maxEntropy: Double = 0

            for i in 0..<samplesPerGap {
                let lba = gap.start + UInt64(i) * step
                guard lba <= gap.end else { break }

                var buf = [UInt8](repeating: 0, count: blockSize)
                let offset = off_t(lba) * off_t(blockSize)
                let bytesRead = pread(fd, &buf, blockSize, offset)
                guard bytesRead == blockSize else { continue }
                totalSampled += 1

                // Skip all-zero blocks (expected for empty space)
                if buf.allSatisfy({ $0 == 0 }) { continue }

                let entropy = shannonEntropy(buf)
                maxEntropy = max(maxEntropy, entropy)
                if entropy > entropyThreshold {
                    highEntropyBlocks += 1
                }
            }

            if highEntropyBlocks > 0 {
                anomalies.append(.filesystem(
                    name: "Hidden Disk Data",
                    path: "/dev/rdisk0",
                    technique: "Hidden Encrypted Disk Region",
                    description: "High-entropy data found in unallocated disk space \(gap.description). \(highEntropyBlocks)/\(totalSampled) sampled blocks have entropy > \(entropyThreshold) bits/byte. Possible encrypted implant storage.",
                    severity: highEntropyBlocks > 2 ? .critical : .high,
                    mitreID: "T1542.001",
                    scannerId: "disk_entropy",
                    enumMethod: "raw /dev/rdisk0 block read + Shannon entropy in unallocated regions",
                    evidence: [
                        "gap_location: \(gap.description)",
                        "gap_lba_range: \(gap.start)-\(gap.end)",
                        "gap_size_bytes: \((gap.end - gap.start + 1) * UInt64(blockSize))",
                        "blocks_sampled: \(totalSampled)",
                        "high_entropy_blocks: \(highEntropyBlocks)",
                        "max_entropy: \(String(format: "%.2f", maxEntropy)) bits/byte",
                    ]))
            }
        }

        logger.info("Disk entropy probe: \(gaps.count) gaps scanned, \(anomalies.count) suspicious regions")
        return anomalies
    }

    // MARK: - Partition Boundaries

    private struct PartBounds {
        let startLBA: UInt64
        let endLBA: UInt64
        let name: String
    }

    private func readPartitionBoundaries() -> [PartBounds]? {
        let fd = open("/dev/rdisk0", O_RDONLY)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        // Read GPT header
        var headerBuf = [UInt8](repeating: 0, count: blockSize)
        guard pread(fd, &headerBuf, blockSize, off_t(blockSize)) == blockSize else { return nil }
        let sig = headerBuf.withUnsafeBytes { $0.load(as: UInt64.self) }
        guard sig == 0x5452415020494645 else { return nil } // "EFI PART"

        let entryLBA = headerBuf.withUnsafeBytes { $0.load(fromByteOffset: 72, as: UInt64.self) }
        let entryCount = headerBuf.withUnsafeBytes { $0.load(fromByteOffset: 80, as: UInt32.self) }
        let entrySize = headerBuf.withUnsafeBytes { $0.load(fromByteOffset: 84, as: UInt32.self) }

        let totalSize = Int(entryCount) * Int(entrySize)
        var entryBuf = [UInt8](repeating: 0, count: totalSize)
        guard pread(fd, &entryBuf, totalSize, off_t(entryLBA) * off_t(blockSize)) == totalSize else { return nil }

        var results: [PartBounds] = []
        for i in 0..<Int(entryCount) {
            let base = i * Int(entrySize)
            guard base + 128 <= entryBuf.count else { break }
            let typeGUID = Array(entryBuf[base..<(base + 16)])
            if typeGUID.allSatisfy({ $0 == 0 }) { continue }

            let startLBA = entryBuf.withUnsafeBytes { $0.load(fromByteOffset: base + 32, as: UInt64.self) }
            let endLBA = entryBuf.withUnsafeBytes { $0.load(fromByteOffset: base + 40, as: UInt64.self) }

            // Parse name
            let nameBytes = Array(entryBuf[(base + 56)..<min(base + 128, entryBuf.count)])
            var chars: [UInt16] = []
            for j in stride(from: 0, to: nameBytes.count - 1, by: 2) {
                let val = UInt16(nameBytes[j]) | (UInt16(nameBytes[j + 1]) << 8)
                if val == 0 { break }
                chars.append(val)
            }
            let name = String(utf16CodeUnits: chars, count: chars.count)
            results.append(PartBounds(startLBA: startLBA, endLBA: endLBA, name: name))
        }
        return results
    }

    private func readDiskTotalLBAs() -> UInt64? {
        let fd = open("/dev/rdisk0", O_RDONLY)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var headerBuf = [UInt8](repeating: 0, count: blockSize)
        guard pread(fd, &headerBuf, blockSize, off_t(blockSize)) == blockSize else { return nil }
        // LastUsableLBA at offset 48
        return headerBuf.withUnsafeBytes { $0.load(fromByteOffset: 48, as: UInt64.self) }
    }

    // MARK: - Shannon Entropy

    private func shannonEntropy(_ data: [UInt8]) -> Double {
        var freq = [Int](repeating: 0, count: 256)
        for byte in data { freq[Int(byte)] += 1 }
        let total = Double(data.count)
        var entropy: Double = 0
        for count in freq where count > 0 {
            let p = Double(count) / total
            entropy -= p * (log(p) / log(2.0))
        }
        return entropy
    }
}
