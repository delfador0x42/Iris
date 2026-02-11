import Foundation
import Combine
import os.log

/// State store for process monitoring
@MainActor
public final class ProcessStore: ObservableObject {

    // MARK: - Singleton

    public static let shared = ProcessStore()

    // MARK: - Published State

    @Published public internal(set) var processes: [ProcessInfo] = [] { didSet { updateDisplayedProcesses() } }
    @Published public internal(set) var processHistory: [ProcessInfo] = []
    @Published public internal(set) var isLoading = false
    @Published public internal(set) var lastUpdate: Date?
    @Published public internal(set) var errorMessage: String?
    @Published public var filterText: String = "" { didSet { updateDisplayedProcesses() } }
    @Published public var showOnlySuspicious: Bool = false { didSet { updateDisplayedProcesses() } }
    @Published public var sortOrder: SortOrder = .name { didSet { updateDisplayedProcesses() } }
    @Published public var viewMode: ViewMode = .monitor

    /// Whether process data comes from ES extension (true) or sysctl polling (false)
    @Published public internal(set) var isUsingEndpointSecurity = false

    /// Whether the ES extension is actively running
    @Published public internal(set) var esExtensionStatus: ESExtensionStatus = .unknown

    public enum ESExtensionStatus: String {
        case unknown = "Unknown"
        case running = "Running"
        case notInstalled = "Not Installed"
        case esDisabled = "ES Disabled"
        case error = "Error"
    }

    // MARK: - Types

    public enum SortOrder: String, CaseIterable {
        case name = "Name"
        case pid = "PID"
        case user = "User"
        case cpu = "CPU"
        case memory = "Memory"
        case suspicious = "Suspicious"
    }

    /// View mode: live monitor (split view) or spawn history timeline
    public enum ViewMode: String, CaseIterable {
        case monitor = "Monitor"
        case history = "History"
    }

    // MARK: - Properties

    let logger = Logger(subsystem: "com.wudan.iris", category: "ProcessStore")
    var xpcConnection: NSXPCConnection?
    var refreshTimer: Timer?

    /// Tracks whether monitoring was active (survives timer stop during reconnection)
    var isMonitoringActive = false

    /// Optional data source for dependency injection (used in tests)
    let dataSource: (any ProcessDataSourceProtocol)?

    /// Refresh interval in seconds.
    /// Rationale: 2 seconds balances UI responsiveness with CPU usage.
    /// Process list changes infrequently, so faster polling adds overhead without benefit.
    let refreshInterval: TimeInterval = 2.0

    /// Tracks PIDs already in history to avoid duplicates. Keyed by (pid, path) string.
    var historySeenKeys: Set<String> = []

    // MARK: - Derived State (updated via didSet, not recomputed per render)

    /// Filtered and sorted processes
    @Published public internal(set) var displayedProcesses: [ProcessInfo] = []

    /// Count of suspicious processes
    @Published public internal(set) var suspiciousCount: Int = 0

    /// Total process count
    public var totalCount: Int { processes.count }

    func updateDisplayedProcesses() {
        suspiciousCount = processes.filter { $0.isSuspicious }.count

        var result = processes
        if !filterText.isEmpty {
            result = result.filter { process in
                process.name.localizedCaseInsensitiveContains(filterText) ||
                process.path.localizedCaseInsensitiveContains(filterText) ||
                String(process.pid).contains(filterText)
            }
        }
        if showOnlySuspicious {
            result = result.filter { $0.isSuspicious }
        }
        switch sortOrder {
        case .name:
            result.sort { $0.name.caseInsensitiveCompare($1.name) == .orderedAscending }
        case .pid:
            result.sort { $0.pid < $1.pid }
        case .user:
            result.sort { $0.userId < $1.userId }
        case .cpu:
            result.sort { ($0.resources?.cpuUsagePercent ?? 0) > ($1.resources?.cpuUsagePercent ?? 0) }
        case .memory:
            result.sort { ($0.resources?.residentMemory ?? 0) > ($1.resources?.residentMemory ?? 0) }
        case .suspicious:
            result.sort { lhs, rhs in
                if lhs.isSuspicious != rhs.isSuspicious { return lhs.isSuspicious }
                return lhs.name.caseInsensitiveCompare(rhs.name) == .orderedAscending
            }
        }
        displayedProcesses = result
    }

    /// Merge current processes into session history. New entries only — deduped by (pid, path).
    func mergeIntoHistory(_ current: [ProcessInfo]) {
        var newEntries: [ProcessInfo] = []
        for process in current {
            let key = "\(process.pid):\(process.path)"
            if !historySeenKeys.contains(key) {
                historySeenKeys.insert(key)
                newEntries.append(process)
            }
        }
        if !newEntries.isEmpty {
            processHistory.append(contentsOf: newEntries)
        }
    }

    // MARK: - Initialization

    /// Initialize with optional data source for dependency injection
    /// - Parameter dataSource: Optional data source (nil uses XPC/local fallback)
    public init(dataSource: (any ProcessDataSourceProtocol)? = nil) {
        self.dataSource = dataSource
    }
}
