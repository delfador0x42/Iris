import Foundation
import NetworkExtension
import os.log

/// Helper for managing the transparent proxy configuration.
/// Follows the same pattern as DNSProxyHelper.
/// After the proxy system extension is activated, NETransparentProxyManager must be configured
/// to tell the system to route HTTP/HTTPS traffic to our NETransparentProxyProvider.
@MainActor
public struct TransparentProxyHelper {

    private static let logger = Logger(subsystem: "com.wudan.iris", category: "TransparentProxyHelper")
    private static let providerBundleID = "com.wudan.iris.proxy.extension"

    // MARK: - Proxy Control

    /// Enable the transparent proxy.
    /// - Returns: true if successfully enabled
    @discardableResult
    public static func enableProxy() async -> Bool {
        logger.info("Enabling transparent proxy...")

        do {
            let manager = try await loadOrCreateManager()

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = providerBundleID
            proto.serverAddress = "localhost"

            manager.protocolConfiguration = proto
            manager.localizedDescription = "Iris HTTPS Proxy"
            manager.isEnabled = true

            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()

            logger.info("Transparent proxy enabled")
            return true

        } catch {
            logger.error("Failed to enable transparent proxy: \(error.localizedDescription)")
            return false
        }
    }

    /// Disable the transparent proxy.
    /// - Returns: true if successfully disabled
    @discardableResult
    public static func disableProxy() async -> Bool {
        logger.info("Disabling transparent proxy...")

        do {
            let manager = try await loadOrCreateManager()
            manager.isEnabled = false
            try await manager.saveToPreferences()

            logger.info("Transparent proxy disabled")
            return true

        } catch {
            logger.error("Failed to disable transparent proxy: \(error.localizedDescription)")
            return false
        }
    }

    /// Completely remove the transparent proxy configuration.
    public static func cleanConfiguration() async {
        logger.info("Cleaning transparent proxy configuration...")

        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            for manager in managers where manager is NETransparentProxyManager {
                if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                   proto.providerBundleIdentifier == providerBundleID {
                    try await manager.removeFromPreferences()
                }
            }
            logger.info("Transparent proxy configuration removed")
        } catch {
            logger.error("Failed to clean transparent proxy configuration: \(error.localizedDescription)")
        }
    }

    // MARK: - Status Checking

    /// Check if the transparent proxy is configured and its current state.
    /// - Returns: Tuple of (isConfigured, isEnabled)
    public static func checkStatus() async -> (isConfigured: Bool, isEnabled: Bool) {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            for manager in managers where manager is NETransparentProxyManager {
                if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                   proto.providerBundleIdentifier == providerBundleID {
                    let enabled = manager.isEnabled
                    logger.info("Transparent proxy status: configured=true, enabled=\(enabled)")
                    return (true, enabled)
                }
            }
            logger.info("Transparent proxy status: not configured")
            return (false, false)
        } catch {
            logger.error("Failed to check transparent proxy status: \(error.localizedDescription)")
            return (false, false)
        }
    }

    // MARK: - Private

    /// Load existing manager or create a new one.
    private static func loadOrCreateManager() async throws -> NETransparentProxyManager {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        for manager in managers where manager is NETransparentProxyManager {
            if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
               proto.providerBundleIdentifier == providerBundleID,
               let transparentProxy = manager as? NETransparentProxyManager {
                return transparentProxy
            }
        }
        return NETransparentProxyManager()
    }
}
