//
//  ProxyStore.swift
//  IrisProxy
//
//  Main state store for the HTTP proxy functionality.
//  Manages connection to proxy extension and captured flows.
//

import Foundation
import SwiftUI
import Combine
import os.log

/// Main store for HTTP proxy state and captured flows.
@MainActor
public final class ProxyStore: ObservableObject {

    // MARK: - Published State

    /// Whether the proxy extension is enabled.
    @Published public private(set) var isEnabled: Bool = false

    /// Whether TLS interception is enabled.
    @Published public private(set) var isInterceptionEnabled: Bool = true

    /// All captured HTTP flows.
    @Published public private(set) var flows: [ProxyCapturedFlow] = []

    /// Currently selected flow for detail view.
    @Published public var selectedFlow: ProxyCapturedFlow?

    /// Current search/filter query.
    @Published public var searchQuery: String = ""

    /// Active method filter (nil = all methods).
    @Published public var methodFilter: String?

    /// Active status code filter (nil = all statuses).
    @Published public var statusFilter: StatusFilter = .all

    /// Whether currently loading flows.
    @Published public private(set) var isLoading: Bool = false

    /// Connection error message.
    @Published public private(set) var errorMessage: String?

    /// Total number of captured flows (including filtered out).
    @Published public private(set) var totalFlowCount: Int = 0

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "ProxyStore")
    private var xpcConnection: NSXPCConnection?
    private var refreshTimer: Timer?
    private var cancellables = Set<AnyCancellable>()

    // MARK: - Singleton

    /// Shared instance for app-wide use.
    public static let shared = ProxyStore()

    // MARK: - Initialization

    public init() {
        setupSearchDebounce()
    }

    deinit {
        // Direct cleanup without calling MainActor-isolated methods
        refreshTimer?.invalidate()
        xpcConnection?.invalidate()
    }

    // MARK: - Connection

    /// Connects to the proxy extension via XPC.
    public func connect() {
        guard xpcConnection == nil else { return }

        logger.info("Connecting to proxy extension...")

        let connection = NSXPCConnection(machServiceName: ProxyXPCInterface.serviceName, options: [])
        connection.remoteObjectInterface = ProxyXPCInterface.createInterface()

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

        // Start periodic refresh
        startRefreshTimer()

        // Initial status check
        Task {
            await refreshStatus()
            await refreshFlows()
        }

        logger.info("Connected to proxy extension")
    }

    /// Disconnects from the proxy extension.
    public func disconnect() {
        stopRefreshTimer()
        xpcConnection?.invalidate()
        xpcConnection = nil
        isEnabled = false
        logger.info("Disconnected from proxy extension")
    }

    private func handleConnectionInvalidated() {
        logger.warning("XPC connection invalidated")
        xpcConnection = nil
        isEnabled = false
        errorMessage = "Connection to proxy extension lost"
    }

    private func handleConnectionInterrupted() {
        logger.warning("XPC connection interrupted")
        errorMessage = "Connection interrupted, retrying..."

        // Try to reconnect
        Task {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            await refreshStatus()
        }
    }

    // MARK: - XPC Methods

    /// Refreshes the proxy status.
    public func refreshStatus() async {
        guard let proxy = getProxy() else {
            isEnabled = false
            return
        }

        await withCheckedContinuation { continuation in
            proxy.getStatus { [weak self] status in
                Task { @MainActor in
                    self?.isEnabled = status["isActive"] as? Bool ?? false
                    self?.isInterceptionEnabled = status["interceptionEnabled"] as? Bool ?? true
                    self?.totalFlowCount = status["flowCount"] as? Int ?? 0
                    self?.errorMessage = nil
                    continuation.resume()
                }
            }
        }
    }

    /// Refreshes the captured flows.
    public func refreshFlows() async {
        guard let proxy = getProxy() else { return }

        isLoading = true

        await withCheckedContinuation { continuation in
            proxy.getFlows { [weak self] flowDataArray in
                Task { @MainActor in
                    self?.parseFlows(flowDataArray)
                    self?.isLoading = false
                    continuation.resume()
                }
            }
        }
    }

    /// Clears all captured flows.
    public func clearFlows() async {
        guard let proxy = getProxy() else { return }

        await withCheckedContinuation { continuation in
            proxy.clearFlows { [weak self] success in
                Task { @MainActor in
                    if success {
                        self?.flows = []
                        self?.totalFlowCount = 0
                        self?.selectedFlow = nil
                    }
                    continuation.resume()
                }
            }
        }
    }

    /// Enables or disables TLS interception.
    public func setInterceptionEnabled(_ enabled: Bool) async {
        guard let proxy = getProxy() else { return }

        await withCheckedContinuation { continuation in
            proxy.setInterceptionEnabled(enabled) { [weak self] success in
                Task { @MainActor in
                    if success {
                        self?.isInterceptionEnabled = enabled
                    }
                    continuation.resume()
                }
            }
        }
    }

    // MARK: - Private Methods

    private func getProxy() -> ProxyXPCProtocol? {
        guard let connection = xpcConnection else {
            errorMessage = "Not connected to proxy extension"
            return nil
        }

        return connection.remoteObjectProxyWithErrorHandler { [weak self] error in
            Task { @MainActor in
                self?.logger.error("XPC error: \(error.localizedDescription)")
                self?.errorMessage = error.localizedDescription
            }
        } as? ProxyXPCProtocol
    }

    private func parseFlows(_ dataArray: [Data]) {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let parsedFlows = dataArray.compactMap { data -> ProxyCapturedFlow? in
            try? decoder.decode(ProxyCapturedFlow.self, from: data)
        }

        // Sort by timestamp (newest first)
        flows = parsedFlows.sorted { $0.timestamp > $1.timestamp }
        totalFlowCount = flows.count
    }

    private func startRefreshTimer() {
        stopRefreshTimer()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refreshFlows()
            }
        }
    }

    private func stopRefreshTimer() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    private func setupSearchDebounce() {
        // Debounce search queries
        $searchQuery
            .debounce(for: .milliseconds(300), scheduler: RunLoop.main)
            .sink { [weak self] _ in
                self?.objectWillChange.send()
            }
            .store(in: &cancellables)
    }

    // MARK: - Filtered Flows

    /// Flows filtered by current search query and filters.
    public var filteredFlows: [ProxyCapturedFlow] {
        var result = flows

        // Apply search query
        if !searchQuery.isEmpty {
            let query = searchQuery.lowercased()
            result = result.filter { flow in
                flow.request.url.lowercased().contains(query) ||
                flow.request.method.lowercased().contains(query) ||
                (flow.processName?.lowercased().contains(query) ?? false)
            }
        }

        // Apply method filter
        if let method = methodFilter {
            result = result.filter { $0.request.method == method }
        }

        // Apply status filter
        switch statusFilter {
        case .all:
            break
        case .success:
            result = result.filter { $0.response?.isSuccess ?? false }
        case .redirect:
            result = result.filter {
                guard let status = $0.response?.statusCode else { return false }
                return status >= 300 && status < 400
            }
        case .clientError:
            result = result.filter {
                guard let status = $0.response?.statusCode else { return false }
                return status >= 400 && status < 500
            }
        case .serverError:
            result = result.filter {
                guard let status = $0.response?.statusCode else { return false }
                return status >= 500
            }
        case .pending:
            result = result.filter { $0.response == nil && $0.error == nil }
        case .error:
            result = result.filter { $0.error != nil }
        }

        return result
    }

    /// Unique methods in captured flows.
    public var availableMethods: [String] {
        Array(Set(flows.map { $0.request.method })).sorted()
    }

    /// Statistics about captured flows.
    public var statistics: FlowStatistics {
        let total = flows.count
        let successful = flows.filter { $0.response?.isSuccess ?? false }.count
        let failed = flows.filter { $0.response?.isError ?? false }.count
        let pending = flows.filter { $0.response == nil && $0.error == nil }.count
        let errors = flows.filter { $0.error != nil }.count

        let totalBytes = flows.reduce(0) { sum, flow in
            sum + flow.request.bodySize + (flow.response?.bodySize ?? 0)
        }

        let avgDuration = flows.compactMap { $0.duration }.reduce(0, +) /
            Double(max(1, flows.filter { $0.duration != nil }.count))

        return FlowStatistics(
            total: total,
            successful: successful,
            failed: failed,
            pending: pending,
            errors: errors,
            totalBytes: totalBytes,
            averageDuration: avgDuration
        )
    }
}

// MARK: - Status Filter

/// Filter for HTTP status codes.
public enum StatusFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case success = "2xx"
    case redirect = "3xx"
    case clientError = "4xx"
    case serverError = "5xx"
    case pending = "Pending"
    case error = "Error"

    public var id: String { rawValue }
}

// MARK: - Flow Statistics

/// Statistics about captured flows.
public struct FlowStatistics {
    public let total: Int
    public let successful: Int
    public let failed: Int
    public let pending: Int
    public let errors: Int
    public let totalBytes: Int
    public let averageDuration: TimeInterval

    public var totalBytesFormatted: String {
        ByteCountFormatter.string(fromByteCount: Int64(totalBytes), countStyle: .file)
    }

    public var averageDurationFormatted: String {
        if averageDuration < 1 {
            return String(format: "%.0fms", averageDuration * 1000)
        } else {
            return String(format: "%.2fs", averageDuration)
        }
    }
}

// MARK: - XPC Types
// ProxyCapturedFlow, ProxyCapturedRequest, ProxyCapturedResponse, and ProxyXPCInterface
// are defined in IrisShared/Protocols/ProxyXPCProtocol.swift
