import SwiftUI
import Combine
import os.log

/// State of the disk scanning operation
public enum DiskScanState: Equatable, Sendable {
    case idle
    case loading  // Loading from cache
    case scanning(progress: ScanProgress)
    case completed(root: DiskNode)
    case cached(root: DiskNode)  // Loaded from cache
    case error(DiskScanError)
    case cancelled

    public static func == (lhs: DiskScanState, rhs: DiskScanState) -> Bool {
        switch (lhs, rhs) {
        case (.idle, .idle): return true
        case (.loading, .loading): return true
        case (.scanning(let a), .scanning(let b)): return a == b
        case (.completed(let a), .completed(let b)): return a == b
        case (.cached(let a), .cached(let b)): return a == b
        case (.error(let a), .error(let b)): return a == b
        case (.cancelled, .cancelled): return true
        default: return false
        }
    }
}

/// Cached disk scan result
private struct DiskScanCache: Codable {
    let rootNode: DiskNode
    let scanDate: Date
    let rootPath: String
}

/// State store for disk usage visualization
@MainActor
public final class DiskUsageStore: ObservableObject {

    // MARK: - Published State

    @Published public private(set) var scanState: DiskScanState = .idle
    @Published public private(set) var rootNode: DiskNode?
    @Published public private(set) var lastScanDate: Date?
    @Published public var expandedNodes: Set<UUID> = []
    @Published public var selectedNode: DiskNode?

    // MARK: - Dependencies

    private let scanner: DiskScanner
    private var scanTask: Task<Void, Never>?
    private let logger = Logger(subsystem: "com.wudan.iris", category: "DiskUsageStore")

    // MARK: - Cache

    private static let cacheFileName = "disk_scan_cache.json"

    private static var cacheURL: URL {
        let cacheDir = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
        return cacheDir.appendingPathComponent(cacheFileName)
    }

    // MARK: - Initialization

    public init(scanner: DiskScanner = DiskScanner()) {
        self.scanner = scanner
    }

    // MARK: - Public Actions

    /// Load cached results if available
    public func loadCachedResults() {
        scanState = .loading

        Task {
            if let cache = loadCache() {
                rootNode = cache.rootNode
                lastScanDate = cache.scanDate
                scanState = .cached(root: cache.rootNode)
                // Auto-expand first level
                expandedNodes = Set(cache.rootNode.children.map { $0.id })
            } else {
                scanState = .idle
            }
        }
    }

    /// Standard refresh method - starts a new disk scan
    public func refresh() {
        startScan()
    }

    /// Alias for refresh() - starts a new disk scan
    public func scan() {
        startScan()
    }

    /// Start scanning from root path
    public func startScan(configuration: DiskScanner.Configuration = .init()) {
        // Cancel any existing scan
        cancelScan()

        scanTask = Task {
            scanState = .scanning(progress: ScanProgress(
                currentPath: configuration.rootPath.path,
                filesScanned: 0,
                totalSizeScanned: 0,
                startTime: Date()
            ))

            do {
                let root = try await scanner.scan(
                    configuration: configuration,
                    onProgress: { [weak self] progress in
                        Task { @MainActor in
                            self?.scanState = .scanning(progress: progress)
                        }
                    }
                )

                rootNode = root
                lastScanDate = Date()
                scanState = .completed(root: root)

                // Auto-expand first level
                expandedNodes = Set(root.children.map { $0.id })

                // Save to cache
                saveCache(rootNode: root, rootPath: configuration.rootPath.path)

            } catch let error as DiskScanError {
                scanState = .error(error)
            } catch {
                scanState = .error(.scanFailed(underlying: error.localizedDescription))
            }
        }
    }

    /// Cancel ongoing scan
    public func cancelScan() {
        scanTask?.cancel()
        Task {
            await scanner.cancel()
        }
        if case .scanning = scanState {
            scanState = .cancelled
        }
    }

    /// Toggle expansion of a node
    public func toggleExpanded(_ node: DiskNode) {
        if expandedNodes.contains(node.id) {
            expandedNodes.remove(node.id)
        } else {
            expandedNodes.insert(node.id)
        }
    }

    /// Reset to initial state
    public func reset() {
        cancelScan()
        rootNode = nil
        expandedNodes = []
        selectedNode = nil
        scanState = .idle
    }

    /// Clear the cache
    public func clearCache() {
        try? FileManager.default.removeItem(at: Self.cacheURL)
    }

    // MARK: - Private Cache Methods

    private func saveCache(rootNode: DiskNode, rootPath: String) {
        let cache = DiskScanCache(
            rootNode: rootNode,
            scanDate: Date(),
            rootPath: rootPath
        )

        do {
            let data = try JSONEncoder().encode(cache)
            try data.write(to: Self.cacheURL)
        } catch {
            logger.error("Failed to save disk scan cache: \(error.localizedDescription)")
        }
    }

    private func loadCache() -> DiskScanCache? {
        guard FileManager.default.fileExists(atPath: Self.cacheURL.path) else {
            return nil
        }

        do {
            let data = try Data(contentsOf: Self.cacheURL)
            return try JSONDecoder().decode(DiskScanCache.self, from: data)
        } catch {
            logger.error("Failed to load disk scan cache: \(error.localizedDescription)")
            return nil
        }
    }
}
