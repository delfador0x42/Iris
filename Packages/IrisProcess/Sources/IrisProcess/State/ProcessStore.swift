import Foundation
import Combine
import os.log

/// State store for process monitoring
@MainActor
public final class ProcessStore: ObservableObject {

    // MARK: - Published State

    @Published public internal(set) var processes: [ProcessInfo] = []
    @Published public internal(set) var isLoading = false
    @Published public internal(set) var lastUpdate: Date?
    @Published public internal(set) var errorMessage: String?
    @Published public var filterText: String = ""
    @Published public var showOnlySuspicious: Bool = false
    @Published public var sortOrder: SortOrder = .name

    // MARK: - Types

    public enum SortOrder: String, CaseIterable {
        case name = "Name"
        case pid = "PID"
        case user = "User"
        case suspicious = "Suspicious"
    }

    // MARK: - Properties

    let logger = Logger(subsystem: "com.wudan.iris", category: "ProcessStore")
    var xpcConnection: NSXPCConnection?
    var refreshTimer: Timer?

    /// Optional data source for dependency injection (used in tests)
    let dataSource: (any ProcessDataSourceProtocol)?

    /// Refresh interval in seconds.
    /// Rationale: 2 seconds balances UI responsiveness with CPU usage.
    /// Process list changes infrequently, so faster polling adds overhead without benefit.
    let refreshInterval: TimeInterval = 2.0

    // MARK: - Computed Properties

    /// Filtered and sorted processes
    public var displayedProcesses: [ProcessInfo] {
        var result = processes

        // Filter by search text
        if !filterText.isEmpty {
            result = result.filter { process in
                process.name.localizedCaseInsensitiveContains(filterText) ||
                process.path.localizedCaseInsensitiveContains(filterText) ||
                String(process.pid).contains(filterText)
            }
        }

        // Filter suspicious only
        if showOnlySuspicious {
            result = result.filter { $0.isSuspicious }
        }

        // Sort
        switch sortOrder {
        case .name:
            result.sort { $0.name.lowercased() < $1.name.lowercased() }
        case .pid:
            result.sort { $0.pid < $1.pid }
        case .user:
            result.sort { $0.userId < $1.userId }
        case .suspicious:
            result.sort { lhs, rhs in
                if lhs.isSuspicious != rhs.isSuspicious {
                    return lhs.isSuspicious
                }
                return lhs.name.lowercased() < rhs.name.lowercased()
            }
        }

        return result
    }

    /// Count of suspicious processes
    public var suspiciousCount: Int {
        processes.filter { $0.isSuspicious }.count
    }

    /// Total process count
    public var totalCount: Int {
        processes.count
    }

    // MARK: - Initialization

    /// Initialize with optional data source for dependency injection
    /// - Parameter dataSource: Optional data source (nil uses XPC/local fallback)
    public init(dataSource: (any ProcessDataSourceProtocol)? = nil) {
        self.dataSource = dataSource
    }
}
