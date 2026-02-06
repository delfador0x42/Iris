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
    @Published public private(set) var networkExtensionState: ExtensionState = .unknown

    /// State of the endpoint extension
    @Published public private(set) var endpointExtensionState: ExtensionState = .unknown

    /// State of the network filter
    @Published public private(set) var filterState: FilterState = .unknown

    /// Last error message
    @Published public private(set) var lastError: String?

    /// Whether Full Disk Access is granted
    @Published public private(set) var hasFullDiskAccess: Bool = false

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "ExtensionManager")

    /// Timer for polling extension status during approval
    private var networkPollTimer: Timer?
    private var endpointPollTimer: Timer?

    /// Track which extension type is being installed (for delegate callbacks)
    private var pendingInstallationType: ExtensionType?

    /// Pending operation for sequencing uninstall → reinstall
    private enum PendingOperation {
        case none
        case uninstallNetworkForReinstall
        case uninstallEndpointForReinstall
        case reinstallAfterCleanup
    }
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
        let (extensionState, filter) = await NetworkFilterHelper.checkStatus()
        networkExtensionState = extensionState
        filterState = filter
    }

    /// Check endpoint extension status
    public func checkEndpointExtensionStatus() async {
        logger.info("Checking endpoint extension status...")
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
    }

    // MARK: - Network Filter Control

    /// Enable the network filter
    public func enableFilter() async {
        filterState = .configuring
        filterState = await NetworkFilterHelper.enableFilter()
        if filterState != .enabled {
            lastError = "Failed to enable network filter"
        }
    }

    /// Disable the network filter
    public func disableFilter() async {
        filterState = .configuring
        filterState = await NetworkFilterHelper.disableFilter()
    }

    /// Completely remove the network filter configuration
    public func cleanNetworkFilterConfiguration() async {
        await NetworkFilterHelper.cleanConfiguration()
        filterState = .disabled
    }

    // MARK: - Clean Reinstall

    /// Perform a clean reinstall of both system extensions
    public func cleanReinstallExtensions() {
        logger.info("Starting clean reinstall of all extensions...")
        lastError = nil

        if networkExtensionState == .installed || networkExtensionState != .notInstalled {
            networkExtensionState = .installing
        }
        if endpointExtensionState == .installed || endpointExtensionState != .notInstalled {
            endpointExtensionState = .installing
        }

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
        let hasAccess = (try? Data(contentsOf: URL(fileURLWithPath: testPath))) != nil
        hasFullDiskAccess = hasAccess
        logger.info("Full Disk Access: \(hasAccess ? "Granted" : "Not granted")")
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

    /// Get state for a specific extension type
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
                await handleSuccessfulCompletion(for: type)

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

    private func handleSuccessfulCompletion(for type: ExtensionType) async {
        switch pendingOperation {
        case .uninstallNetworkForReinstall:
            await continueReinstallAfterNetworkUninstall()

        case .uninstallEndpointForReinstall:
            await continueReinstallAfterEndpointUninstall()

        case .reinstallAfterCleanup:
            await completeReinstall(for: type)

        case .none:
            await completeNormalInstall(for: type)
        }
    }

    private func continueReinstallAfterNetworkUninstall() async {
        logger.info("Network extension uninstalled, now uninstalling endpoint...")
        pendingOperation = .uninstallEndpointForReinstall
        networkExtensionState = .notInstalled

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: ExtensionType.endpoint.bundleIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private func continueReinstallAfterEndpointUninstall() async {
        logger.info("Endpoint extension uninstalled, cleaning config and reinstalling...")
        endpointExtensionState = .notInstalled

        await cleanNetworkFilterConfiguration()
        try? await Task.sleep(nanoseconds: 500_000_000)

        pendingOperation = .reinstallAfterCleanup
        pendingInstallationType = .network
        networkExtensionState = .installing

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: ExtensionType.network.bundleIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private func completeReinstall(for type: ExtensionType) async {
        if type == .network {
            networkExtensionState = .installed
            await enableFilter()
            onNetworkExtensionReady?()

            pendingOperation = .none
            installExtension(.endpoint)
        } else {
            endpointExtensionState = .installed
            onEndpointExtensionReady?()
            pendingOperation = .none
        }
    }

    private func completeNormalInstall(for type: ExtensionType) async {
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

    nonisolated public func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        Task { @MainActor in
            let type = pendingInstallationType ?? .network
            let nsError = error as NSError

            logger.error("\(type.displayName) extension error: \(nsError.localizedDescription)")
            logger.error("Error domain: \(nsError.domain), code: \(nsError.code)")

            // During clean reinstall, continue sequence even if uninstall fails
            if await handleReinstallError(for: type) {
                return
            }

            // Normal error handling
            handleInstallError(error, for: type)
        }
    }

    private func handleReinstallError(for type: ExtensionType) async -> Bool {
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
            return true

        case .uninstallEndpointForReinstall:
            logger.info("Endpoint uninstall failed (may not exist), continuing to reinstall...")
            endpointExtensionState = .notInstalled

            await cleanNetworkFilterConfiguration()
            try? await Task.sleep(nanoseconds: 500_000_000)

            pendingOperation = .reinstallAfterCleanup
            pendingInstallationType = .network
            networkExtensionState = .installing

            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: ExtensionType.network.bundleIdentifier,
                queue: .main
            )
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
            return true

        default:
            return false
        }
    }

    private func handleInstallError(_ error: Error, for type: ExtensionType) {
        pendingOperation = .none
        let nsError = error as NSError

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
