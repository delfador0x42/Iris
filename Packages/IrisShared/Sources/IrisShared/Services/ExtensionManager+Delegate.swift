import Foundation
import SystemExtensions
import NetworkExtension
import os.log

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
            case .proxy:
                proxyExtensionState = .needsUserApproval
            case .dns:
                dnsExtensionState = .needsUserApproval
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
                case .proxy:
                    proxyExtensionState = .needsUserApproval
                case .dns:
                    dnsExtensionState = .needsUserApproval
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

            // During clean reinstall, continue sequence even if uninstall fails
            if await handleReinstallError(for: type) {
                return
            }

            // Normal error handling
            handleInstallError(error, for: type)
        }
    }
}

// MARK: - Delegate Helper Methods

@MainActor
extension ExtensionManager {

    func handleSuccessfulCompletion(for type: ExtensionType) async {
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

    func handleReinstallError(for type: ExtensionType) async -> Bool {
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

    func handleInstallError(_ error: Error, for type: ExtensionType) {
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

        setExtensionState(type, to: failedState)

        lastError = "\(error.localizedDescription)\n\(errorDetails)"
        pendingInstallationType = nil
    }
}
