import Foundation
import SystemExtensions
import NetworkExtension
import os.log

// MARK: - Installation & Uninstallation

@MainActor
extension ExtensionManager {

    /// Install a specific extension
    public func installExtension(_ type: ExtensionType) {
        logger.info("Requesting \(type.displayName) extension installation...")
        pendingInstallationType = type

        switch type {
        case .network:
            networkExtensionState = .installing
        case .endpoint:
            endpointExtensionState = .installing
        case .dns:
            dnsExtensionState = .installing
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

    // MARK: - Reinstall Helpers

    func continueReinstallAfterNetworkUninstall() async {
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

    func continueReinstallAfterEndpointUninstall() async {
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

    func completeReinstall(for type: ExtensionType) async {
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

    func completeNormalInstall(for type: ExtensionType) async {
        switch type {
        case .network:
            networkExtensionState = .installed
            await enableFilter()
            onNetworkExtensionReady?()
        case .endpoint:
            endpointExtensionState = .installed
            onEndpointExtensionReady?()
        case .dns:
            dnsExtensionState = .installed
            await enableDNSProxy()
            onDNSExtensionReady?()
        }
    }
}
