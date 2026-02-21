import Foundation
import Combine
import SystemExtensions
import NetworkExtension
import AppKit
import os.log

/// Manages the installation and lifecycle of system extensions.
/// Two extensions: Endpoint (EndpointSecurity) and Network (unified proxy).
@MainActor
public class ExtensionManager: NSObject, ObservableObject {

    // MARK: - Published State

    /// State of the endpoint extension (EndpointSecurity)
    @Published public internal(set) var endpointExtensionState: ExtensionState = .unknown

    /// State of the network extension (unified proxy + DNS + firewall)
    @Published public internal(set) var networkExtensionState: ExtensionState = .unknown

    /// Last error message
    @Published public internal(set) var lastError: String?

    /// Whether Full Disk Access is granted
    @Published public internal(set) var hasFullDiskAccess: Bool = false

    // MARK: - Properties

    let logger = Logger(subsystem: "com.wudan.iris", category: "ExtensionManager")

    /// Timer for polling extension status during approval
    var endpointPollTimer: Timer?
    var networkPollTimer: Timer?

    /// Track which extension type is being installed
    var pendingInstallationType: ExtensionType?

    /// Resolve extension type from OSSystemExtensionRequest using its bundle identifier.
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
    public var onEndpointExtensionReady: (() -> Void)?
    public var onNetworkExtensionReady: (() -> Void)?

    // MARK: - Singleton

    public static let shared = ExtensionManager()

    private override init() {
        super.init()
        Task {
            await checkAllExtensionStatuses()
        }
    }

    // MARK: - Convenience Properties

    /// Check if endpoint extension is ready
    public var isEndpointExtensionReady: Bool {
        endpointExtensionState.isReady
    }

    /// Check if network extension is ready
    public var isNetworkExtensionReady: Bool {
        networkExtensionState.isReady
    }

    /// Whether any extension is currently installing
    public var isAnyExtensionInstalling: Bool {
        endpointExtensionState == .installing || networkExtensionState == .installing
    }

    /// Check if all extensions are ready
    public var areAllExtensionsReady: Bool {
        isEndpointExtensionReady && isNetworkExtensionReady
    }

    /// Get state for a specific extension type
    public func state(for type: ExtensionType) -> ExtensionState {
        switch type {
        case .endpoint: return endpointExtensionState
        case .network: return networkExtensionState
        }
    }
}
