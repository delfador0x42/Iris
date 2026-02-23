import Foundation
import os.log

/// Checks CPU architecture of every running process via proc_pidinfo(PROC_PIDARCHINFO).
///
/// On Apple Silicon, all native processes should be ARM64.
/// Any x86_64 process runs via Rosetta — suspicious for system daemons.
/// A system daemon running x86_64 means either:
///   1. Legitimate Rosetta process (rare for system)
///   2. Cross-architecture injection / malware binary
///
/// Also detects hidden architecture inconsistencies by comparing
/// proc_pidinfo result vs the Mach-O header of the on-disk binary.
public actor ArchitectureContradictionProbe: ContradictionProbe {
    public static let shared = ArchitectureContradictionProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "ArchProbe")

    public nonisolated let id = "architecture"
    public nonisolated let name = "Process Architecture"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "All system processes are running native ARM64 code on Apple Silicon",
        groundTruth: "proc_pidinfo(PROC_PIDARCHINFO) reads kernel process architecture, cross-checked with disk binary Mach-O header",
        adversaryCost: "Must hook proc_pidinfo AND replace the on-disk binary — two independent sources",
        positiveDetection: "Shows any system daemon running x86_64 via Rosetta, or architecture mismatch between runtime and disk",
        falsePositiveRate: "Very low — system daemons are always ARM64 on Apple Silicon Mac"
    )

    // System paths that should ALWAYS be ARM64
    private static let criticalPaths: Set<String> = [
        "/sbin/launchd",
        "/usr/libexec/trustd",
        "/usr/libexec/amfid",
        "/usr/libexec/securityd",
        "/usr/libexec/syspolicyd",
        "/usr/sbin/mDNSResponder",
        "/usr/libexec/logd",
        "/usr/libexec/configd",
        "/usr/libexec/opendirectoryd",
        "/usr/sbin/sshd",
        "/usr/libexec/taskgated",
        "/usr/sbin/notifyd",
        "/usr/libexec/watchdogd",
        "/usr/libexec/UserEventAgent",
    ]

    // proc_pidinfo constants
    private static let PROC_PIDARCHINFO: Int32 = 19

    // CPU types (mach/machine.h)
    private static let CPU_TYPE_ARM64: Int32 = 0x0100000C   // CPU_TYPE_ARM | CPU_ARCH_ABI64
    private static let CPU_TYPE_X86_64: Int32 = 0x01000007  // CPU_TYPE_X86 | CPU_ARCH_ABI64

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        let snapshot = ProcessSnapshot.capture()
        var x86Count = 0
        var arm64Count = 0
        var criticalX86: [(name: String, path: String)] = []

        for pid in snapshot.pids {
            let path = snapshot.path(for: pid) ?? ""
            let name = snapshot.name(for: pid) ?? "unknown"

            // Read architecture via proc_pidinfo
            var archInfo = proc_archinfo()
            let size = proc_pidinfo(pid, Self.PROC_PIDARCHINFO, 0, &archInfo,
                                    Int32(MemoryLayout<proc_archinfo>.size))
            guard size == MemoryLayout<proc_archinfo>.size else { continue }

            if archInfo.p_cputype == Self.CPU_TYPE_ARM64 {
                arm64Count += 1
            } else if archInfo.p_cputype == Self.CPU_TYPE_X86_64 {
                x86Count += 1
                // Check if this is a critical system path
                if Self.criticalPaths.contains(path) {
                    criticalX86.append((name: name, path: path))
                    hasContradiction = true
                }
            }
        }

        // Comparison 1: Overall architecture census
        comparisons.append(SourceComparison(
            label: "architecture census",
            sourceA: SourceValue("proc_pidinfo", "\(arm64Count) ARM64, \(x86Count) x86_64"),
            sourceB: SourceValue("expected (Apple Silicon)", "all system ARM64"),
            matches: criticalX86.isEmpty))

        // Comparison 2: Each critical x86_64 process is a separate finding
        for proc in criticalX86 {
            comparisons.append(SourceComparison(
                label: "\(proc.name) architecture",
                sourceA: SourceValue("proc_pidinfo runtime", "x86_64 (Rosetta)"),
                sourceB: SourceValue("expected", "ARM64 (native)"),
                matches: false))
        }

        // Comparison 3: Cross-check a sample of processes — disk Mach-O header vs runtime
        for pid in snapshot.pids.prefix(20) {
            let path = snapshot.path(for: pid)
            guard !path.isEmpty else { continue }
            let name = snapshot.name(for: pid)

            var archInfo = proc_archinfo()
            let size = proc_pidinfo(pid, Self.PROC_PIDARCHINFO, 0, &archInfo,
                                    Int32(MemoryLayout<proc_archinfo>.size))
            guard size == MemoryLayout<proc_archinfo>.size else { continue }

            if let diskArch = readDiskMachOArch(path: path) {
                let runtimeArch = archInfo.p_cputype
                // For fat/universal binaries, the disk may list both. Only flag if
                // runtime is x86_64 but disk binary is arm64-only
                if runtimeArch == Self.CPU_TYPE_X86_64 && diskArch == Self.CPU_TYPE_ARM64 {
                    hasContradiction = true
                    comparisons.append(SourceComparison(
                        label: "\(name) disk vs runtime arch",
                        sourceA: SourceValue("disk Mach-O", "ARM64"),
                        sourceB: SourceValue("proc_pidinfo", "x86_64"),
                        matches: false))
                }
            }
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        let verdict: ProbeVerdict
        let message: String

        if comparisons.isEmpty {
            verdict = .degraded
            message = "Could not enumerate process architectures"
        } else if hasContradiction {
            let issues = comparisons.filter { !$0.matches }.count
            verdict = .contradiction
            message = "CONTRADICTION: \(issues) architecture anomaly(ies) — \(criticalX86.count) critical x86_64 processes"
            logger.critical("ARCHITECTURE CONTRADICTION: \(criticalX86.map(\.name))")
        } else {
            verdict = .consistent
            message = "\(arm64Count) ARM64 processes, \(x86Count) x86_64 (Rosetta) — all critical are native"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    // MARK: - Disk Mach-O

    /// Read the CPU type from the Mach-O header on disk.
    /// Returns nil for unreadable files, the CPU type for thin binaries.
    private func readDiskMachOArch(path: String) -> Int32? {
        guard let fh = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? fh.close() }
        guard let data = try? fh.read(upToCount: 8), data.count >= 4 else { return nil }
        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }
        switch magic {
        case 0xFEEDFACF: // MH_MAGIC_64
            return data.withUnsafeBytes { ptr -> Int32 in
                guard ptr.count >= 8 else { return 0 }
                return ptr.load(fromByteOffset: 4, as: Int32.self)
            }
        case 0xCFFAEDFE: // MH_CIGAM_64 (byte-swapped)
            return data.withUnsafeBytes { ptr -> Int32 in
                guard ptr.count >= 8 else { return 0 }
                return Int32(bigEndian: ptr.load(fromByteOffset: 4, as: Int32.self))
            }
        default:
            return nil // FAT binary or unknown — skip
        }
    }
}

// proc_archinfo is defined in libproc but not always in Swift headers
private struct proc_archinfo {
    var p_cputype: Int32 = 0
    var p_cpusubtype: Int32 = 0
}
