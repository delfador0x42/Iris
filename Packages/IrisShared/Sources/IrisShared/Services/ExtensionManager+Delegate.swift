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
        let log = Logger(subsystem: "com.wudan.iris", category: "ExtensionManager")
        log.info("[DELEGATE] actionForReplacingExtension: existing=\(existing.bundleIdentifier) v\(existing.bundleShortVersion), new=\(ext.bundleIdentifier) v\(ext.bundleShortVersion) → replacing")
        return .replace
    }

    nonisolated public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            let type = pendingInstallationType ?? .network
            logger.warning("[DELEGATE] requestNeedsUserApproval for \(type.displayName) (bundle: \(type.bundleIdentifier)). User must approve in System Settings > Privacy & Security.")

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
                let opDesc = String(describing: pendingOperation)
                logger.info("[DELEGATE] didFinishWithResult: COMPLETED for \(type.displayName) (pendingOp: \(opDesc))")
                await handleSuccessfulCompletion(for: type)

            case .willCompleteAfterReboot:
                logger.warning("[DELEGATE] didFinishWithResult: WILL_COMPLETE_AFTER_REBOOT for \(type.displayName)")
                pendingOperation = .none
                setExtensionState(type, to: .needsUserApproval)

            @unknown default:
                logger.error("[DELEGATE] didFinishWithResult: UNKNOWN result (\(result.rawValue)) for \(type.displayName)")
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

            logger.error("[DELEGATE] didFailWithError for \(type.displayName): domain=\(nsError.domain) code=\(nsError.code) desc=\(nsError.localizedDescription)")

            if let underlying = nsError.userInfo[NSUnderlyingErrorKey] as? NSError {
                logger.error("[DELEGATE]   underlying: domain=\(underlying.domain) code=\(underlying.code) desc=\(underlying.localizedDescription)")
            }

            for (key, value) in nsError.userInfo where key != NSUnderlyingErrorKey {
                logger.error("[DELEGATE]   userInfo[\(key)] = \(String(describing: value))")
            }

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
        let opDesc = String(describing: pendingOperation)
        logger.info("[LIFECYCLE] handleSuccessfulCompletion for \(type.displayName), pendingOp=\(opDesc)")

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
            logger.info("[REINSTALL] Network uninstall failed (may not exist), continuing to endpoint...")
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
            logger.info("[REINSTALL] Endpoint uninstall failed (may not exist), continuing to reinstall...")
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

        var errorDetails = "domain=\(nsError.domain) code=\(nsError.code)"
        if let underlyingError = nsError.userInfo[NSUnderlyingErrorKey] as? NSError {
            errorDetails += " underlying=\(underlyingError.domain):\(underlyingError.code)"
        }

        let failedState: ExtensionState

        if nsError.domain == OSSystemExtensionErrorDomain {
            switch nsError.code {
            case OSSystemExtensionError.requestCanceled.rawValue:
                logger.warning("[ERROR] \(type.displayName): request was CANCELED by user")
                failedState = .notInstalled
            case OSSystemExtensionError.authorizationRequired.rawValue:
                logger.warning("[ERROR] \(type.displayName): authorization REQUIRED — needs admin approval")
                failedState = .needsUserApproval
            case OSSystemExtensionError.extensionNotFound.rawValue:
                logger.error("[ERROR] \(type.displayName): extension NOT FOUND in app bundle — check that \(type.bundleIdentifier) target is embedded")
                failedState = .failed("Extension not found in App bundle")
            case OSSystemExtensionError.codeSignatureInvalid.rawValue:
                logger.error("[ERROR] \(type.displayName): CODE SIGNATURE INVALID — rebuild and re-sign")
                failedState = .failed("Code signature invalid")
            case 4: // duplicateExtension (code 4)
                logger.error("[ERROR] \(type.displayName): DUPLICATE extension — another copy may be installed")
                failedState = .failed("Duplicate extension — try clean reinstall")
            default:
                logger.error("[ERROR] \(type.displayName): OSSystemExtension error \(errorDetails)")
                failedState = .failed("\(error.localizedDescription)\n\(errorDetails)")
            }
        } else {
            logger.error("[ERROR] \(type.displayName): non-sysext error \(errorDetails): \(error.localizedDescription)")
            failedState = .failed("\(error.localizedDescription)\n\(errorDetails)")
        }

        setExtensionState(type, to: failedState)
        lastError = "\(type.displayName): \(error.localizedDescription) (\(errorDetails))"
        pendingInstallationType = nil
    }
}
