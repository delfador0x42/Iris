import Foundation

/// Represents a node in the filesystem tree with disk usage information
public struct DiskNode: Identifiable, Sendable, Equatable, Codable {
    public let id: UUID
    public let name: String
    public let path: URL
    public let size: UInt64
    public let isDirectory: Bool
    public var children: [DiskNode]
    public let depth: Int
    public let permissionDenied: Bool

    public nonisolated init(
        id: UUID = UUID(),
        name: String,
        path: URL,
        size: UInt64,
        isDirectory: Bool,
        children: [DiskNode] = [],
        depth: Int = 0,
        permissionDenied: Bool = false
    ) {
        self.id = id
        self.name = name
        self.path = path
        self.size = size
        self.isDirectory = isDirectory
        self.children = children
        self.depth = depth
        self.permissionDenied = permissionDenied
    }

    /// Percentage of parent size (0.0 to 1.0)
    public func percentageOf(total: UInt64) -> Double {
        guard total > 0 else { return 0 }
        return Double(size) / Double(total)
    }

    /// Whether this node has expandable children
    public var hasChildren: Bool {
        isDirectory && !children.isEmpty
    }
}
