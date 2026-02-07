import Foundation
import NetworkExtension
import os.log

/// Helper for managing the DNS proxy configuration.
/// Follows the same pattern as NetworkFilterHelper.
/// After the DNS system extension is activated, NEDNSProxyManager must be configured
/// to tell the system to route DNS traffic to our DNSProxyProvider.
@MainActor
public struct DNSProxyHelper {

    private static let logger = Logger(subsystem: "com.wudan.iris", category: "DNSProxyHelper")

    // MARK: - DNS Proxy Control

    /// Enable the DNS proxy.
    /// - Returns: true if successfully enabled
    @discardableResult
    public static func enableDNSProxy() async -> Bool {
        logger.info("Enabling DNS proxy...")

        do {
            let manager = NEDNSProxyManager.shared()
            try await manager.loadFromPreferences()

            let proto = NEDNSProxyProviderProtocol()
            proto.providerBundleIdentifier = "com.wudan.iris.dns.extension"
            // serverAddress is required even if we use DoH internally
            proto.serverAddress = "1.1.1.1"

            manager.providerProtocol = proto
            manager.localizedDescription = "Iris Encrypted DNS"
            manager.isEnabled = true

            try await manager.saveToPreferences()

            logger.info("DNS proxy enabled")
            return true

        } catch {
            logger.error("Failed to enable DNS proxy: \(error.localizedDescription)")
            return false
        }
    }

    /// Disable the DNS proxy.
    /// - Returns: true if successfully disabled
    @discardableResult
    public static func disableDNSProxy() async -> Bool {
        logger.info("Disabling DNS proxy...")

        do {
            let manager = NEDNSProxyManager.shared()
            try await manager.loadFromPreferences()

            manager.isEnabled = false
            try await manager.saveToPreferences()

            logger.info("DNS proxy disabled")
            return true

        } catch {
            logger.error("Failed to disable DNS proxy: \(error.localizedDescription)")
            return false
        }
    }

    /// Completely remove the DNS proxy configuration.
    public static func cleanConfiguration() async {
        logger.info("Cleaning DNS proxy configuration...")

        do {
            let manager = NEDNSProxyManager.shared()
            try await manager.loadFromPreferences()

            try await manager.removeFromPreferences()
            logger.info("DNS proxy configuration removed")
        } catch {
            logger.error("Failed to clean DNS proxy configuration: \(error.localizedDescription)")
        }
    }

    // MARK: - Status Checking

    /// Check if the DNS proxy is configured and its current state.
    /// - Returns: Tuple of (isConfigured, isEnabled)
    public static func checkStatus() async -> (isConfigured: Bool, isEnabled: Bool) {
        do {
            let manager = NEDNSProxyManager.shared()
            try await manager.loadFromPreferences()

            let isConfigured = manager.providerProtocol != nil
            let isEnabled = manager.isEnabled

            logger.info("DNS proxy status: configured=\(isConfigured), enabled=\(isEnabled)")
            return (isConfigured, isEnabled)

        } catch {
            logger.error("Failed to check DNS proxy status: \(error.localizedDescription)")
            return (false, false)
        }
    }
}
