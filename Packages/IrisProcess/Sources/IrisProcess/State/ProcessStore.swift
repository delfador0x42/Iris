import Foundation
import Combine
import os.log

/// State store for process monitoring
@MainActor
public final class ProcessStore: ObservableObject {

    // MARK: - Published State

    @Published public private(set) var processes: [ProcessInfo] = []
    @Published public private(set) var isLoading = false
    @Published public private(set) var lastUpdate: Date?
    @Published public private(set) var errorMessage: String?
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

    private let logger = Logger(subsystem: "com.wudan.iris", category: "ProcessStore")
    private var xpcConnection: NSXPCConnection?
    private var refreshTimer: Timer?

    /// Optional data source for dependency injection (used in tests)
    private let dataSource: (any ProcessDataSourceProtocol)?

    /// Refresh interval in seconds.
    /// Rationale: 2 seconds balances UI responsiveness with CPU usage.
    /// Process list changes infrequently, so faster polling adds overhead without benefit.
    private let refreshInterval: TimeInterval = 2.0

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

    // MARK: - Data Fetching

    /// Standard refresh method - reloads all process data
    public func refresh() async {
        await refreshProcesses()
    }

    /// Fetch processes - uses data source if available, otherwise XPC/local fallback
    public func refreshProcesses() async {
        isLoading = processes.isEmpty

        // Use injected data source if available (for testing)
        if let dataSource = dataSource {
            await fetchProcessesViaDataSource(dataSource)
        } else if let connection = xpcConnection {
            // Try XPC first
            await fetchProcessesViaXPC(connection)
        } else {
            // Fallback to local enumeration
            await fetchProcessesLocally()
        }

        // Check man pages for processes (in background, don't block refresh)
        Task {
            await checkManPagesForProcesses()
        }

        lastUpdate = Date()
        isLoading = false
    }

    /// Check if processes have man pages
    private func checkManPagesForProcesses() async {
        let manPageStore = ManPageStore.shared

        // Get unique command names to check
        let commandNames = Set(processes.map { $0.name })

        // Pre-cache man page existence for all commands
        await manPageStore.preCacheManPages(for: Array(commandNames))

        // Update processes with man page status
        for i in processes.indices {
            let hasManPage = manPageStore.hasManPage(for: processes[i].name)
            if processes[i].hasManPage != hasManPage {
                processes[i].hasManPage = hasManPage
            }
        }
    }

    private func fetchProcessesViaDataSource(_ dataSource: any ProcessDataSourceProtocol) async {
        do {
            let dataArray = try await dataSource.fetchProcesses()
            processProcessData(dataArray)
        } catch {
            logger.error("Data source error: \(error.localizedDescription)")
            errorMessage = error.localizedDescription
        }
    }

    private func fetchProcessesViaXPC(_ connection: NSXPCConnection) async {
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ [weak self] error in
            Task { @MainActor in
                self?.logger.error("XPC error: \(error.localizedDescription)")
                self?.errorMessage = error.localizedDescription
            }
        }) as? EndpointXPCProtocol else {
            await fetchProcessesLocally()
            return
        }

        await withCheckedContinuation { continuation in
            proxy.getProcesses { [weak self] dataArray in
                Task { @MainActor in
                    self?.processProcessData(dataArray)
                    continuation.resume()
                }
            }
        }
    }

    private func processProcessData(_ dataArray: [Data]) {
        let decoder = JSONDecoder()
        processes = dataArray.compactMap { data -> ProcessInfo? in
            try? decoder.decode(ProcessInfo.self, from: data)
        }
    }

    /// Enumerate processes locally using BSD APIs
    private func fetchProcessesLocally() async {
        var newProcesses: [ProcessInfo] = []

        // Get number of processes
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0

        // First call to get size
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else {
            logger.error("Failed to get process list size")
            return
        }

        // Allocate buffer
        let count = size / MemoryLayout<kinfo_proc>.stride
        var procList = [kinfo_proc](repeating: kinfo_proc(), count: count)

        // Second call to get data
        guard sysctl(&mib, 4, &procList, &size, nil, 0) == 0 else {
            logger.error("Failed to get process list")
            return
        }

        let actualCount = size / MemoryLayout<kinfo_proc>.stride

        for i in 0..<actualCount {
            let proc = procList[i]
            let pid = proc.kp_proc.p_pid

            guard pid > 0 else { continue }

            if let processInfo = getProcessInfo(pid: pid, kinfo: proc) {
                newProcesses.append(processInfo)
            }
        }

        processes = newProcesses
    }

    private func getProcessInfo(pid: pid_t, kinfo: kinfo_proc) -> ProcessInfo? {
        // Get process path
        var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let pathLength = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        guard pathLength > 0 else { return nil }

        let path = String(cString: pathBuffer)
        let name = (path as NSString).lastPathComponent

        // Get ppid, uid from kinfo
        let ppid = kinfo.kp_eproc.e_ppid
        let uid = kinfo.kp_eproc.e_ucred.cr_uid
        // Use uid for gid as fallback (cr_gid not available in this struct)
        let gid = kinfo.kp_eproc.e_pcred.p_rgid

        // Get code signing info
        let codeSigningInfo = getCodeSigningInfo(forPath: path)

        return ProcessInfo(
            pid: pid,
            ppid: ppid,
            path: path,
            name: name,
            arguments: [],
            userId: uid,
            groupId: gid,
            codeSigningInfo: codeSigningInfo,
            timestamp: Date()
        )
    }

    private func getCodeSigningInfo(forPath path: String) -> ProcessInfo.CodeSigningInfo? {
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL

        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return nil
        }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let signingInfo = info as? [String: Any] else {
            return nil
        }

        let teamId = signingInfo["teamid"] as? String
        let signingId = signingInfo["identifier"] as? String
        let flags = (signingInfo["flags"] as? UInt32) ?? 0

        // Check for Apple signature
        let isAppleSigned = teamId == nil && signingId?.hasPrefix("com.apple.") == true

        // Check if platform binary
        let isPlatformBinary = isAppleSigned && (flags & 0x0001) != 0  // CS_VALID

        return ProcessInfo.CodeSigningInfo(
            teamId: teamId,
            signingId: signingId,
            flags: flags,
            isAppleSigned: isAppleSigned,
            isPlatformBinary: isPlatformBinary
        )
    }

    // MARK: - Connection Management

    /// Connect to the security extension via XPC
    public func connect() {
        guard xpcConnection == nil else {
            logger.info("Already connected to extension")
            return
        }

        logger.info("Connecting to endpoint security extension for process monitoring...")

        let connection = NSXPCConnection(
            machServiceName: EndpointXPCService.extensionServiceName,
            options: []
        )

        connection.remoteObjectInterface = NSXPCInterface(
            with: EndpointXPCProtocol.self
        )

        connection.invalidationHandler = { [weak self] in
            Task { @MainActor in
                self?.handleConnectionInvalidated()
            }
        }

        connection.interruptionHandler = { [weak self] in
            Task { @MainActor in
                self?.handleConnectionInterrupted()
            }
        }

        connection.resume()
        xpcConnection = connection
        errorMessage = nil

        logger.info("Connected to endpoint security extension")
    }

    /// Disconnect from the extension
    public func disconnect() {
        xpcConnection?.invalidate()
        xpcConnection = nil
        logger.info("Disconnected from endpoint security extension")
    }

    private func handleConnectionInvalidated() {
        logger.warning("XPC connection invalidated")
        xpcConnection = nil
    }

    private func handleConnectionInterrupted() {
        logger.warning("XPC connection interrupted")
        errorMessage = "Connection to extension interrupted"
    }

    // MARK: - Timer Management

    public func startAutoRefresh() {
        stopAutoRefresh()

        refreshTimer = Timer.scheduledTimer(withTimeInterval: refreshInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refreshProcesses()
            }
        }

        // Try to connect to XPC (will fall back to local if fails)
        connect()

        // Initial fetch
        Task {
            await refreshProcesses()
        }
    }

    public func stopAutoRefresh() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }
}

// MARK: - Username Resolution

extension ProcessStore {
    /// Get username for a user ID
    public static func username(forUID uid: UInt32) -> String {
        switch uid {
        case 0: return "root"
        case 501: return "user"
        default:
            if let pw = getpwuid(uid) {
                return String(cString: pw.pointee.pw_name)
            }
            return "\(uid)"
        }
    }
}
