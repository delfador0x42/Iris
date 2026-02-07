import Foundation
import Darwin
import os.log

/// Collects CPU, memory, and file descriptor metrics per process.
/// Uses proc_pidinfo(PROC_PIDTASKINFO) for CPU/memory and PROC_PIDLISTFDS for open files.
/// Tracks previous CPU time samples to compute delta-based CPU percentage.
public actor ProcessResourceCollector {
    public static let shared = ProcessResourceCollector()

    private struct CPUSample {
        let totalTimeNs: UInt64
        let wallClockNs: UInt64
    }

    /// Previous CPU time samples for delta computation
    private var previousSamples: [pid_t: CPUSample] = [:]

    /// Mach timebase for converting Mach time units to nanoseconds
    private let timebaseNumer: UInt64
    private let timebaseDenom: UInt64

    private let logger = Logger(subsystem: "com.wudan.iris", category: "ResourceCollector")

    private init() {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        timebaseNumer = UInt64(info.numer)
        timebaseDenom = UInt64(info.denom)
    }

    private func machToNanos(_ mach: UInt64) -> UInt64 {
        mach * timebaseNumer / timebaseDenom
    }

    /// Collect resource metrics for a single process
    public func collect(pid: pid_t) -> ProcessResourceInfo? {
        var taskInfo = proc_taskinfo()
        let size = MemoryLayout<proc_taskinfo>.stride

        let ret = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &taskInfo, Int32(size))
        guard ret == size else { return nil }

        // CPU time: convert Mach absolute time to nanoseconds
        let cpuTimeMach = taskInfo.pti_total_user + taskInfo.pti_total_system
        let cpuTimeNs = machToNanos(cpuTimeMach)
        let nowNs = DispatchTime.now().uptimeNanoseconds

        // Compute CPU% as delta from previous sample
        var cpuPercent = 0.0
        if let prev = previousSamples[pid] {
            let deltaCPU = cpuTimeNs.subtractingReportingOverflow(prev.totalTimeNs)
            let deltaWall = nowNs.subtractingReportingOverflow(prev.wallClockNs)
            if !deltaCPU.overflow && !deltaWall.overflow && deltaWall.partialValue > 0 {
                cpuPercent = Double(deltaCPU.partialValue) / Double(deltaWall.partialValue) * 100.0
            }
        }

        previousSamples[pid] = CPUSample(totalTimeNs: cpuTimeNs, wallClockNs: nowNs)

        let fdCount = getOpenFileCount(pid: pid)

        return ProcessResourceInfo(
            cpuUsagePercent: cpuPercent,
            residentMemory: taskInfo.pti_resident_size,
            virtualMemory: taskInfo.pti_virtual_size,
            threadCount: taskInfo.pti_threadnum,
            openFileCount: fdCount
        )
    }

    /// Count of open file descriptors for a process
    private func getOpenFileCount(pid: pid_t) -> Int32 {
        let bufSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bufSize > 0 else { return 0 }
        return bufSize / Int32(MemoryLayout<proc_fdinfo>.stride)
    }

    /// Remove stale entries for processes that no longer exist
    public func pruneStale(activePids: Set<pid_t>) {
        previousSamples = previousSamples.filter { activePids.contains($0.key) }
    }
}
