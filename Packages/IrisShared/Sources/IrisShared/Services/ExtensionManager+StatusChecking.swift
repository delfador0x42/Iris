import Foundation
import SystemExtensions
import NetworkExtension
import os.log

// MARK: - Status Checking & Polling

@MainActor
extension ExtensionManager {

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

    func stopNetworkPolling() {
        networkPollTimer?.invalidate()
        networkPollTimer = nil
    }

    func stopEndpointPolling() {
        endpointPollTimer?.invalidate()
        endpointPollTimer = nil
    }
}
