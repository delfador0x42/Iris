import Foundation
import NetworkExtension
import SystemExtensions
import os.log

// MARK: - Installation & Uninstallation

@MainActor
extension ExtensionManager {

  /// Install a specific extension
  public func installExtension(_ type: ExtensionType) {
    logger.info(
      "[INSTALL] Requesting \(type.displayName) extension installation (bundle: \(type.bundleIdentifier))"
    )
    pendingInstallationType = type

    switch type {
    case .endpoint:
      endpointExtensionState = .installing
    case .network:
      networkExtensionState = .installing
    }
    lastError = nil

    let request = OSSystemExtensionRequest.activationRequest(
      forExtensionWithIdentifier: type.bundleIdentifier,
      queue: .main
    )
    request.delegate = self
    logger.info("[INSTALL] Submitting OSSystemExtensionRequest for \(type.displayName)")
    OSSystemExtensionManager.shared.submitRequest(request)
    logger.info(
      "[INSTALL] Request submitted for \(type.displayName) — waiting for delegate callback")
  }

  /// Uninstall a specific extension
  public func uninstallExtension(_ type: ExtensionType) {
    logger.info(
      "[UNINSTALL] Requesting \(type.displayName) extension uninstallation (bundle: \(type.bundleIdentifier))"
    )
    pendingInstallationType = type

    let request = OSSystemExtensionRequest.deactivationRequest(
      forExtensionWithIdentifier: type.bundleIdentifier,
      queue: .main
    )
    request.delegate = self
    OSSystemExtensionManager.shared.submitRequest(request)
    logger.info("[UNINSTALL] Request submitted for \(type.displayName)")
  }

  /// Install all extensions
  public func installAllExtensions() {
    for type in ExtensionType.allCases {
      installExtension(type)
    }
  }

  // MARK: - Clean Reinstall

  /// Perform a clean reinstall of all system extensions
  public func cleanReinstallExtensions() {
    logger.info("Starting clean reinstall of all extensions...")
    lastError = nil

    for type in ExtensionType.allCases {
      let current = state(for: type)
      if current != .notInstalled {
        setExtensionState(type, to: .installing)
      }
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

    await cleanTransparentProxyConfiguration()
    try? await Task.sleep(nanoseconds: 500_000_000)

    pendingOperation = .reinstallAfterCleanup
    pendingInstallationType = .endpoint
    endpointExtensionState = .installing

    let request = OSSystemExtensionRequest.activationRequest(
      forExtensionWithIdentifier: ExtensionType.endpoint.bundleIdentifier,
      queue: .main
    )
    request.delegate = self
    OSSystemExtensionManager.shared.submitRequest(request)
  }

  /// Sequence: endpoint → network
  func completeReinstall(for type: ExtensionType) async {
    await completeNormalInstall(for: type)

    switch type {
    case .endpoint:
      installExtension(.network)
    case .network:
      pendingOperation = .none
    }
  }

  func completeNormalInstall(for type: ExtensionType) async {
    switch type {
    case .endpoint:
      endpointExtensionState = .installed
      onEndpointExtensionReady?()
    case .network:
      networkExtensionState = .installed
      await enableTransparentProxy()
      onNetworkExtensionReady?()
    }
  }

  /// Helper to set extension state by type
  func setExtensionState(_ type: ExtensionType, to state: ExtensionState) {
    switch type {
    case .endpoint: endpointExtensionState = state
    case .network: networkExtensionState = state
    }
  }
}
