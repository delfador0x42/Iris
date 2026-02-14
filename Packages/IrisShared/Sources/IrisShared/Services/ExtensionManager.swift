import Foundation
import Combine
import SystemExtensions
import NetworkExtension
import AppKit
import os.log

/// Manages the installation and lifecycle of system extensions
@MainActor
public class ExtensionManager: NSObject, ObservableObject {

    // MARK: - Published State

    /// State of the network extension
    @Published public internal(set) var networkExtensionState: ExtensionState = .unknown

    /// State of the endpoint extension
    @Published public internal(set) var endpointExtensionState: ExtensionState = .unknown

    /// State of the HTTPS proxy extension
    @Published public internal(set) var proxyExtensionState: ExtensionState = .unknown

    /// State of the DNS proxy extension
    @Published public internal(set) var dnsExtensionState: ExtensionState = .unknown

    /// State of the network filter
    @Published public internal(set) var filterState: FilterState = .unknown

    /// Last error message
    @Published public internal(set) var lastError: String?

    /// Whether Full Disk Access is granted
    @Published public internal(set) var hasFullDiskAccess: Bool = false

    // MARK: - Properties

    let logger = Logger(subsystem: "com.wudan.iris", category: "ExtensionManager")

    /// Timer for polling extension status during approval
    var networkPollTimer: Timer?
    var endpointPollTimer: Timer?

    /// Track which extension type is being installed (legacy — prefer resolveType(for:))
    var pendingInstallationType: ExtensionType?

    /// Resolve extension type from OSSystemExtensionRequest using its bundle identifier.
    /// Falls back to pendingInstallationType for single-extension operations.
    func resolveType(for request: OSSystemExtensionRequest) -> ExtensionType {
        ExtensionType(bundleIdentifier: request.identifier) ?? pendingInstallationType ?? .network
    }

    /// Pending operation for sequencing uninstall -> reinstall
    enum PendingOperation {
        case none
        case uninstallNetworkForReinstall
        case uninstallEndpointForReinstall
        case reinstallAfterCleanup
    }
    var pendingOperation: PendingOperation = .none

    /// Callbacks when extensions become ready
    public var onNetworkExtensionReady: (() -> Void)?
    public var onEndpointExtensionReady: (() -> Void)?
    public var onProxyExtensionReady: (() -> Void)?
    public var onDNSExtensionReady: (() -> Void)?

    // MARK: - Singleton

    public static let shared = ExtensionManager()

    private override init() {
        super.init()
        Task {
            await checkAllExtensionStatuses()
        }
        startObservingConfigurationChanges()
    }

    // MARK: - Configuration Change Observation

    func startObservingConfigurationChanges() {
        NotificationCenter.default.addObserver(
            forName: NSNotification.Name.NEFilterConfigurationDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.logger.info("Filter configuration changed, checking status...")
                await self?.checkNetworkExtensionStatus()
                if self?.networkExtensionState == .installed {
                    self?.onNetworkExtensionReady?()
                }
            }
        }
    }

    // MARK: - Convenience Properties

    /// Check if network extension is ready
    public var isNetworkExtensionReady: Bool {
        networkExtensionState.isReady
    }

    /// Check if endpoint extension is ready
    public var isEndpointExtensionReady: Bool {
        endpointExtensionState.isReady
    }

    /// Check if proxy extension is ready
    public var isProxyExtensionReady: Bool {
        proxyExtensionState.isReady
    }

    /// Check if DNS extension is ready
    public var isDNSExtensionReady: Bool {
        dnsExtensionState.isReady
    }

    /// Whether any extension is currently installing (disables reinstall button)
    public var isAnyExtensionInstalling: Bool {
        networkExtensionState == .installing || endpointExtensionState == .installing
            || proxyExtensionState == .installing || dnsExtensionState == .installing
    }

    /// Check if all extensions are ready
    public var areAllExtensionsReady: Bool {
        isNetworkExtensionReady && isEndpointExtensionReady
            && isProxyExtensionReady && isDNSExtensionReady
    }

    /// Get state for a specific extension type
    public func state(for type: ExtensionType) -> ExtensionState {
        switch type {
        case .network: return networkExtensionState
        case .endpoint: return endpointExtensionState
        case .proxy: return proxyExtensionState
        case .dns: return dnsExtensionState
        }
    }
}
