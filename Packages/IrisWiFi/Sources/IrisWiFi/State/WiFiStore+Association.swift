import Foundation
import CoreWLAN
import os.log

// MARK: - Network Association

@MainActor
extension WiFiStore {

    /// Associate to a scanned network
    /// - Parameters:
    ///   - network: The network to connect to
    ///   - password: Password for the network (nil for open networks)
    /// - Returns: Whether the operation succeeded
    public func associate(to network: WiFiNetwork, password: String?) async -> Bool {
        guard let interface = wifiClient.interface() else {
            errorMessage = "No WiFi interface available"
            return false
        }

        guard interface.powerOn() else {
            errorMessage = "WiFi is powered off"
            return false
        }

        // Find the CWNetwork object from our cached scan results
        guard let cwNetwork = interface.cachedScanResults()?.first(where: { $0.bssid == network.bssid }) else {
            // If not in cache, try a fresh scan
            do {
                let networks = try interface.scanForNetworks(withSSID: network.ssid?.data(using: .utf8))
                guard let found = networks.first(where: { $0.bssid == network.bssid }) else {
                    errorMessage = "Network not found"
                    return false
                }

                try interface.associate(to: found, password: password)
            } catch {
                logger.error("Failed to associate: \(error.localizedDescription)")
                errorMessage = "Failed to connect: \(error.localizedDescription)"
                return false
            }

            await refresh()
            logger.info("Associated to network: \(network.ssid ?? "unknown")")
            return true
        }

        do {
            try interface.associate(to: cwNetwork, password: password)
            await refresh()
            logger.info("Associated to network: \(network.ssid ?? "unknown")")
            return true
        } catch {
            logger.error("Failed to associate: \(error.localizedDescription)")
            errorMessage = "Failed to connect: \(error.localizedDescription)"
            return false
        }
    }

    /// Disassociate from the current network
    public func disassociate() {
        guard let interface = wifiClient.interface() else {
            errorMessage = "No WiFi interface available"
            return
        }

        interface.disassociate()
        logger.info("Disassociated from network")

        // Clear cached MCS/NSS since we're no longer connected
        cachedMCS = nil
        cachedNSS = nil
        lastMCSFetch = nil

        Task {
            await refresh()
        }
    }
}
