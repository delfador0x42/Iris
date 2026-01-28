import Foundation
import IrisShared

/// Actor-based disk scanner for thread-safe filesystem traversal
public actor DiskScanner {

    // MARK: - Configuration

    public struct Configuration: Sendable {
        public let rootPath: URL
        public let maxDepth: Int
        public let ignoreHidden: Bool
        public let topNItems: Int
        public let ignoredPaths: Set<String>

        public init(
            rootPath: URL = URL(fileURLWithPath: "/"),
            maxDepth: Int = 20,
            ignoreHidden: Bool = false,
            topNItems: Int = 20,
            ignoredPaths: Set<String> = ["/System/Volumes", "/private/var/vm"]
        ) {
            self.rootPath = rootPath
            self.maxDepth = maxDepth
            self.ignoreHidden = ignoreHidden
            self.topNItems = topNItems
            self.ignoredPaths = ignoredPaths
        }
    }

    // MARK: - State

    private var isCancelled = false
    private var filesScanned = 0
    private var totalSizeScanned: UInt64 = 0
    private var currentPath = ""
    private var startTime = Date()

    // MARK: - Progress Callback Type

    public typealias ProgressCallback = @Sendable (ScanProgress) -> Void

    // MARK: - Public API

    public init() {}

    /// Scan disk from root path with progress updates
    public func scan(
        configuration: Configuration,
        onProgress: ProgressCallback? = nil
    ) async throws -> DiskNode {
        // Reset state
        isCancelled = false
        filesScanned = 0
        totalSizeScanned = 0
        currentPath = configuration.rootPath.path
        startTime = Date()

        let root = try await walkDirectory(
            at: configuration.rootPath,
            depth: 0,
            configuration: configuration,
            onProgress: onProgress
        )

        guard !isCancelled else {
            throw DiskScanError.cancelled
        }

        // Sort children by size descending and limit to top N
        return sortAndLimit(node: root, topN: configuration.topNItems)
    }

    /// Cancel ongoing scan
    public func cancel() {
        isCancelled = true
    }

    // MARK: - Private Implementation

    private func walkDirectory(
        at url: URL,
        depth: Int,
        configuration: Configuration,
        onProgress: ProgressCallback?
    ) async throws -> DiskNode {

        guard !isCancelled else {
            throw DiskScanError.cancelled
        }

        // Update progress periodically
        currentPath = url.path
        if let callback = onProgress, filesScanned % 100 == 0 {
            let progress = ScanProgress(
                currentPath: currentPath,
                filesScanned: filesScanned,
                totalSizeScanned: totalSizeScanned,
                startTime: startTime
            )
            callback(progress)
        }

        let fileManager = FileManager.default
        let resourceKeys: Set<URLResourceKey> = [
            .isDirectoryKey,
            .totalFileSizeKey,
            .fileSizeKey,
            .isHiddenKey
        ]

        // Get attributes for current item
        let attributes = try? url.resourceValues(forKeys: resourceKeys)
        let isDirectory = attributes?.isDirectory ?? false
        let fileSize = UInt64(attributes?.totalFileSize ?? attributes?.fileSize ?? 0)

        // Check for ignored paths
        if configuration.ignoredPaths.contains(url.path) {
            return DiskNode(
                name: url.lastPathComponent,
                path: url,
                size: 0,
                isDirectory: isDirectory,
                depth: depth
            )
        }

        // Handle hidden files
        if configuration.ignoreHidden && (attributes?.isHidden ?? false) {
            return DiskNode(
                name: url.lastPathComponent,
                path: url,
                size: 0,
                isDirectory: isDirectory,
                depth: depth
            )
        }

        // For files, return size directly
        if !isDirectory {
            filesScanned += 1
            totalSizeScanned += fileSize
            return DiskNode(
                name: url.lastPathComponent,
                path: url,
                size: fileSize,
                isDirectory: false,
                depth: depth
            )
        }

        // For directories, recurse into children
        guard depth < configuration.maxDepth else {
            return DiskNode(
                name: url.lastPathComponent,
                path: url,
                size: 0,
                isDirectory: true,
                depth: depth
            )
        }

        var children: [DiskNode] = []
        var totalChildSize: UInt64 = 0
        var permissionDenied = false

        do {
            let contents = try fileManager.contentsOfDirectory(
                at: url,
                includingPropertiesForKeys: Array(resourceKeys),
                options: configuration.ignoreHidden ? [.skipsHiddenFiles] : []
            )

            // Process children concurrently with TaskGroup for parallelism
            children = try await withThrowingTaskGroup(of: DiskNode.self) { group in
                for childURL in contents {
                    group.addTask {
                        try await self.walkDirectory(
                            at: childURL,
                            depth: depth + 1,
                            configuration: configuration,
                            onProgress: onProgress
                        )
                    }
                }

                var results: [DiskNode] = []
                for try await child in group {
                    results.append(child)
                    totalChildSize += child.size
                }
                return results
            }
        } catch let error as NSError {
            // Check for permission denied error
            if error.domain == NSCocoaErrorDomain && error.code == NSFileReadNoPermissionError {
                permissionDenied = true
            }
            // Don't throw, just return with 0 size (matches dust behavior)
        } catch {
            // Other errors - just continue with empty children
        }

        return DiskNode(
            name: url.lastPathComponent,
            path: url,
            size: totalChildSize,
            isDirectory: true,
            children: children,
            depth: depth,
            permissionDenied: permissionDenied
        )
    }

    /// Sort nodes by size descending and limit children to top N
    private func sortAndLimit(node: DiskNode, topN: Int) -> DiskNode {
        let sortedChildren = node.children
            .sorted { $0.size > $1.size }
            .prefix(topN)
            .map { sortAndLimit(node: $0, topN: topN) }

        return DiskNode(
            id: node.id,
            name: node.name,
            path: node.path,
            size: node.size,
            isDirectory: node.isDirectory,
            children: Array(sortedChildren),
            depth: node.depth,
            permissionDenied: node.permissionDenied
        )
    }
}
