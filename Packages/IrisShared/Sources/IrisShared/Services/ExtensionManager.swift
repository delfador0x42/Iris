import Foundation
import Combine
import SystemExtensions
import NetworkExtension
import AppKit
import os.log

// MARK: - Extension Type

/// Types of system extensions managed by Iris
public enum ExtensionType: CaseIterable {
    case network
    case endpoint

    public var bundleIdentifier: String {
        switch self {
        case .network: return "com.wudan.iris.network.extension"
        case .endpoint: return "com.wudan.iris.endpoint.extension"
        }
    }

    public var displayName: String {
        switch self {
        case .network: return "Network Filter"
        case .endpoint: return "Process Monitor"
        }
    }

    public var description: String {
        switch self {
        case .network: return "Monitors and filters network connections"
        case .endpoint: return "Monitors process execution"
        }
    }
}

/// Manages the installation and lifecycle of system extensions
@MainActor
public class ExtensionManager: NSObject, ObservableObject {

    // MARK: - Published State

    /// State of the network extension
    @Published public private(set) var networkExtensionState: ExtensionState = .unknown

    /// State of the endpoint extension
    @Published public private(set) var endpointExtensionState: ExtensionState = .unknown

    /// State of the network filter
    @Published public private(set) var filterState: FilterState = .unknown

    /// Last error message
    @Published public private(set) var lastError: String?

    /// Whether Full Disk Access is granted
    @Published public private(set) var hasFullDiskAccess: Bool = false

    // MARK: - Types

    public enum ExtensionState: Equatable {
        case unknown
        case notInstalled
        case installing
        case needsUserApproval
        case installed
        case failed(String)

        public var description: String {
            switch self {
            case .unknown: return "Unknown"
            case .notInstalled: return "Not Installed"
            case .installing: return "Installing..."
            case .needsUserApproval: return "Needs Approval"
            case .installed: return "Installed"
            case .failed(let error): return "Failed: \(error)"
            }
        }

        public var isReady: Bool {
            self == .installed
        }
    }

    public enum FilterState: Equatable {
        case unknown
        case disabled
        case enabled
        case configuring

        public var description: String {
            switch self {
            case .unknown: return "Unknown"
            case .disabled: return "Disabled"
            case .enabled: return "Enabled"
            case .configuring: return "Configuring..."
            }
        }
    }

    /// Pending operation for sequencing uninstall → reinstall
    private enum PendingOperation {
        case none
        case uninstallNetworkForReinstall
        case uninstallEndpointForReinstall
        case reinstallAfterCleanup
    }

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "ExtensionManager")

    /// Timer for polling extension status during approval
    private var networkPollTimer: Timer?
    private var endpointPollTimer: Timer?

    /// Track which extension type is being installed (for delegate callbacks)
    private var pendingInstallationType: ExtensionType?

    /// Track pending operation sequence for clean reinstall
    private var pendingOperation: PendingOperation = .none

    /// Callbacks when extensions become ready
    public var onNetworkExtensionReady: (() -> Void)?
    public var onEndpointExtensionReady: (() -> Void)?

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

    private func startObservingConfigurationChanges() {
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

    // MARK: - Status Checking

    /// Check status of all extensions
    public func checkAllExtensionStatuses() async {
        await checkNetworkExtensionStatus()
        await checkEndpointExtensionStatus()
        await checkFullDiskAccess()
    }

    /// Check network extension status via NEFilterManager
    public func checkNetworkExtensionStatus() async {
        logger.info("Checking network extension status...")

        do {
            let manager = NEFilterManager.shared()
            try await manager.loadFromPreferences()

            if manager.providerConfiguration != nil {
                logger.info("Network extension is installed")
                networkExtensionState = .installed
                filterState = manager.isEnabled ? .enabled : .disabled
            } else {
                logger.info("Network extension not installed")
                networkExtensionState = .notInstalled
                filterState = .disabled
            }
        } catch {
            logger.error("Failed to check network extension status: \(error.localizedDescription)")
            networkExtensionState = .notInstalled
            filterState = .unknown
        }
    }

    /// Check endpoint extension status
    /// Note: ES extensions don't have a built-in status check like NE, so we try XPC
    public func checkEndpointExtensionStatus() async {
        logger.info("Checking endpoint extension status...")
        // For ES extensions, we can't easily check status without XPC
        // The UI will handle showing the appropriate state based on XPC connectivity
        // For now, we assume it's in the same state as network if we can't verify
        if endpointExtensionState == .unknown {
            endpointExtensionState = .notInstalled
        }
    }

    // MARK: - Polling

    /// Start polling for network extension approval
    public func startPollingForNetworkApproval() {
        stopNetworkPolling()
        logger.info("Starting to poll for network extension approval...")

        networkPollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.checkNetworkExtensionStatus()
                if self?.networkExtensionState == .installed {
                    self?.stopNetworkPolling()
                    self?.onNetworkExtensionReady?()
                }
            }
        }
    }

    /// Start polling for endpoint extension approval
    public func startPollingForEndpointApproval() {
        stopEndpointPolling()
        logger.info("Starting to poll for endpoint extension approval...")

        endpointPollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                // ES extensions need different status checking
                // For now we'll poll based on the pending state clearing
                if self?.endpointExtensionState == .installed {
                    self?.stopEndpointPolling()
                    self?.onEndpointExtensionReady?()
                }
            }
        }
    }

    private func stopNetworkPolling() {
        networkPollTimer?.invalidate()
        networkPollTimer = nil
    }

    private func stopEndpointPolling() {
        endpointPollTimer?.invalidate()
        endpointPollTimer = nil
    }

    // MARK: - Installation

    /// Install a specific extension
    public func installExtension(_ type: ExtensionType) {
        logger.info("Requesting \(type.displayName) extension installation...")
        pendingInstallationType = type

        switch type {
        case .network:
            networkExtensionState = .installing
        case .endpoint:
            endpointExtensionState = .installing
        }
        lastError = nil

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: type.bundleIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Uninstall a specific extension
    public func uninstallExtension(_ type: ExtensionType) {
        logger.info("Requesting \(type.displayName) extension uninstallation...")
        pendingInstallationType = type

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: type.bundleIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Install both extensions
    public func installAllExtensions() {
        installExtension(.network)
        // Note: You may want to wait for network to complete before installing endpoint
        // For now, we install them sequentially through the delegate callbacks
    }

    // MARK: - Network Filter Control

    /// Enable the network filter
    public func enableFilter() async {
        logger.info("Enabling network filter...")
        filterState = .configuring

        do {
            let manager = NEFilterManager.shared()
            try await manager.loadFromPreferences()

            let filterConfig = NEFilterProviderConfiguration()
            filterConfig.filterPackets = false
            filterConfig.filterSockets = true

            manager.providerConfiguration = filterConfig
            manager.localizedDescription = "Iris Network Monitor"
            manager.isEnabled = true

            try await manager.saveToPreferences()

            filterState = .enabled
            logger.info("Network filter enabled")

        } catch {
            logger.error("Failed to enable filter: \(error.localizedDescription)")
            filterState = .disabled
            lastError = error.localizedDescription
        }
    }

    /// Disable the network filter
    public func disableFilter() async {
        logger.info("Disabling network filter...")
        filterState = .configuring

        do {
            let manager = NEFilterManager.shared()
            try await manager.loadFromPreferences()

            manager.isEnabled = false
            try await manager.saveToPreferences()

            filterState = .disabled
            logger.info("Network filter disabled")

        } catch {
            logger.error("Failed to disable filter: \(error.localizedDescription)")
            lastError = error.localizedDescription
        }
    }

    /// Completely remove the network filter configuration
    public func cleanNetworkFilterConfiguration() async {
        logger.info("Cleaning network filter configuration...")

        do {
            let manager = NEFilterManager.shared()
            try await manager.loadFromPreferences()

            manager.providerConfiguration = nil
            manager.isEnabled = false

            try await manager.saveToPreferences()
            logger.info("Network filter configuration cleaned")
            filterState = .disabled
        } catch {
            logger.error("Failed to clean filter configuration: \(error.localizedDescription)")
        }
    }

    /// Perform a clean reinstall of both system extensions
    /// This uninstalls existing extensions, clears configs, and reinstalls fresh
    public func cleanReinstallExtensions() {
        logger.info("Starting clean reinstall of all extensions...")
        lastError = nil

        // Update states to show we're working
        if networkExtensionState == .installed || networkExtensionState != .notInstalled {
            networkExtensionState = .installing
        }
        if endpointExtensionState == .installed || endpointExtensionState != .notInstalled {
            endpointExtensionState = .installing
        }

        // Start the sequence: uninstall network first
        pendingOperation = .uninstallNetworkForReinstall

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: ExtensionType.network.bundleIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: - Full Disk Access

    /// Check if Full Disk Access is granted (required for Endpoint Security)
    public func checkFullDiskAccess() async {
        let testPath = "/Library/Application Support/com.apple.TCC/TCC.db"
        // Actually try to read the file - isReadableFile can give false positives
        // TCC will block the actual read even if file permissions allow it
        let hasAccess = (try? Data(contentsOf: URL(fileURLWithPath: testPath))) != nil
        hasFullDiskAccess = hasAccess

        if hasAccess {
            logger.info("Full Disk Access: Granted")
        } else {
            logger.info("Full Disk Access: Not granted")
        }
    }

    // MARK: - System Settings

    /// Open System Settings to Privacy & Security
    public func openSystemSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }

    /// Open System Settings to Full Disk Access
    public func openFullDiskAccessSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
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

    /// Check if all extensions are ready
    public var areAllExtensionsReady: Bool {
        isNetworkExtensionReady && isEndpointExtensionReady
    }

    // MARK: - Helper to get state for a type

    public func state(for type: ExtensionType) -> ExtensionState {
        switch type {
        case .network: return networkExtensionState
        case .endpoint: return endpointExtensionState
        }
    }
}

// MARK: - OSSystemExtensionRequestDelegate

extension ExtensionManager: OSSystemExtensionRequestDelegate {

    nonisolated public func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }

    nonisolated public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            let type = pendingInstallationType ?? .network
            logger.info("\(type.displayName) extension needs user approval")

            switch type {
            case .network:
                networkExtensionState = .needsUserApproval
                startPollingForNetworkApproval()
            case .endpoint:
                endpointExtensionState = .needsUserApproval
                startPollingForEndpointApproval()
            }
        }
    }

    nonisolated public func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in
            let type = pendingInstallationType ?? .network

            switch result {
            case .completed:
                logger.info("\(type.displayName) extension request completed successfully")

                // Handle clean reinstall sequence
                switch pendingOperation {
                case .uninstallNetworkForReinstall:
                    logger.info("Network extension uninstalled, now uninstalling endpoint...")
                    pendingOperation = .uninstallEndpointForReinstall
                    networkExtensionState = .notInstalled

                    // Uninstall endpoint next
                    let request = OSSystemExtensionRequest.deactivationRequest(
                        forExtensionWithIdentifier: ExtensionType.endpoint.bundleIdentifier,
                        queue: .main
                    )
                    request.delegate = self
                    OSSystemExtensionManager.shared.submitRequest(request)

                case .uninstallEndpointForReinstall:
                    logger.info("Endpoint extension uninstalled, cleaning config and reinstalling...")
                    endpointExtensionState = .notInstalled

                    // Clean the filter configuration, then reinstall
                    Task {
                        await self.cleanNetworkFilterConfiguration()

                        // Small delay to let system settle
                        try? await Task.sleep(nanoseconds: 500_000_000)

                        // Now reinstall network extension
                        self.pendingOperation = .reinstallAfterCleanup
                        self.pendingInstallationType = .network
                        self.networkExtensionState = .installing

                        let request = OSSystemExtensionRequest.activationRequest(
                            forExtensionWithIdentifier: ExtensionType.network.bundleIdentifier,
                            queue: .main
                        )
                        request.delegate = self
                        OSSystemExtensionManager.shared.submitRequest(request)
                    }

                case .reinstallAfterCleanup:
                    // Network reinstalled, now install endpoint
                    if type == .network {
                        networkExtensionState = .installed
                        await enableFilter()
                        onNetworkExtensionReady?()

                        // Now install endpoint
                        pendingOperation = .none
                        installExtension(.endpoint)
                    } else {
                        // Endpoint installed - we're done
                        endpointExtensionState = .installed
                        onEndpointExtensionReady?()
                        pendingOperation = .none
                    }

                case .none:
                    // Normal installation flow (not part of reinstall sequence)
                    switch type {
                    case .network:
                        networkExtensionState = .installed
                        await enableFilter()
                        onNetworkExtensionReady?()
                    case .endpoint:
                        endpointExtensionState = .installed
                        onEndpointExtensionReady?()
                    }
                }

            case .willCompleteAfterReboot:
                logger.info("\(type.displayName) extension will complete after reboot")
                pendingOperation = .none
                switch type {
                case .network:
                    networkExtensionState = .needsUserApproval
                case .endpoint:
                    endpointExtensionState = .needsUserApproval
                }

            @unknown default:
                logger.warning("Unknown extension result")
                pendingOperation = .none
            }

            pendingInstallationType = nil
        }
    }

    nonisolated public func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        Task { @MainActor in
            let type = pendingInstallationType ?? .network
            let nsError = error as NSError

            logger.error("\(type.displayName) extension error: \(nsError.localizedDescription)")
            logger.error("Error domain: \(nsError.domain), code: \(nsError.code)")

            // During clean reinstall, continue the sequence even if uninstall fails
            // (extension might not have been installed in the first place)
            switch pendingOperation {
            case .uninstallNetworkForReinstall:
                logger.info("Network uninstall failed (may not exist), continuing to endpoint...")
                pendingOperation = .uninstallEndpointForReinstall
                networkExtensionState = .notInstalled

                let request = OSSystemExtensionRequest.deactivationRequest(
                    forExtensionWithIdentifier: ExtensionType.endpoint.bundleIdentifier,
                    queue: .main
                )
                request.delegate = self
                OSSystemExtensionManager.shared.submitRequest(request)
                return

            case .uninstallEndpointForReinstall:
                logger.info("Endpoint uninstall failed (may not exist), continuing to reinstall...")
                endpointExtensionState = .notInstalled

                Task {
                    await self.cleanNetworkFilterConfiguration()
                    try? await Task.sleep(nanoseconds: 500_000_000)

                    self.pendingOperation = .reinstallAfterCleanup
                    self.pendingInstallationType = .network
                    self.networkExtensionState = .installing

                    let request = OSSystemExtensionRequest.activationRequest(
                        forExtensionWithIdentifier: ExtensionType.network.bundleIdentifier,
                        queue: .main
                    )
                    request.delegate = self
                    OSSystemExtensionManager.shared.submitRequest(request)
                }
                return

            default:
                break
            }

            // Normal error handling for non-sequence operations
            pendingOperation = .none

            var errorDetails = "Code: \(nsError.code)"
            if let underlyingError = nsError.userInfo[NSUnderlyingErrorKey] as? NSError {
                errorDetails += "\nUnderlying: \(underlyingError.localizedDescription)"
            }

            let failedState: ExtensionState

            if nsError.domain == OSSystemExtensionErrorDomain {
                switch nsError.code {
                case OSSystemExtensionError.requestCanceled.rawValue:
                    failedState = .notInstalled
                case OSSystemExtensionError.authorizationRequired.rawValue:
                    failedState = .needsUserApproval
                case OSSystemExtensionError.extensionNotFound.rawValue:
                    failedState = .failed("Extension not found in App bundle")
                case OSSystemExtensionError.codeSignatureInvalid.rawValue:
                    failedState = .failed("Code signature invalid")
                default:
                    failedState = .failed("\(error.localizedDescription)\n\(errorDetails)")
                }
            } else {
                failedState = .failed("\(error.localizedDescription)\n\(errorDetails)")
            }

            switch type {
            case .network:
                networkExtensionState = failedState
            case .endpoint:
                endpointExtensionState = failedState
            }

            lastError = "\(error.localizedDescription)\n\(errorDetails)"
            pendingInstallationType = nil
        }
    }
}
