import Foundation

/// Progress information during disk scanning
public struct ScanProgress: Equatable, Sendable {
    public let currentPath: String
    public let filesScanned: Int
    public let totalSizeScanned: UInt64
    public let startTime: Date

    public nonisolated init(
        currentPath: String,
        filesScanned: Int,
        totalSizeScanned: UInt64,
        startTime: Date
    ) {
        self.currentPath = currentPath
        self.filesScanned = filesScanned
        self.totalSizeScanned = totalSizeScanned
        self.startTime = startTime
    }

    /// Elapsed time since scan started
    public var elapsedTime: TimeInterval {
        Date().timeIntervalSince(startTime)
    }
}
