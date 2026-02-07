import Foundation

/// Resource usage metrics for a running process
public struct ProcessResourceInfo: Sendable, Codable, Equatable {
    /// CPU usage as percentage (0-100+, can exceed 100 on multi-core)
    public let cpuUsagePercent: Double
    /// Resident memory in bytes
    public let residentMemory: UInt64
    /// Virtual memory size in bytes
    public let virtualMemory: UInt64
    /// Number of active threads
    public let threadCount: Int32
    /// Number of open file descriptors
    public let openFileCount: Int32

    public init(
        cpuUsagePercent: Double,
        residentMemory: UInt64,
        virtualMemory: UInt64,
        threadCount: Int32,
        openFileCount: Int32
    ) {
        self.cpuUsagePercent = cpuUsagePercent
        self.residentMemory = residentMemory
        self.virtualMemory = virtualMemory
        self.threadCount = threadCount
        self.openFileCount = openFileCount
    }

    /// Formatted resident memory string (e.g. "45.2 MB")
    public var formattedMemory: String {
        ByteCountFormatter.string(fromByteCount: Int64(residentMemory), countStyle: .memory)
    }

    /// Formatted CPU percentage (e.g. "12.3%")
    public var formattedCPU: String {
        String(format: "%.1f%%", cpuUsagePercent)
    }
}
