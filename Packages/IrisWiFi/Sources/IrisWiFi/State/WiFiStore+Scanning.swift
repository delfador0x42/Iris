import Foundation
import CoreWLAN
import os.log

// MARK: - Scanning & Power Control

@MainActor
extension WiFiStore {

    /// Scan for nearby networks
    public func scan() async {
        guard let interface = wifiClient.interface() else {
            errorMessage = "No WiFi interface available"
            return
        }

        guard interface.powerOn() else {
            errorMessage = "WiFi is powered off"
            return
        }

        isScanning = true
        errorMessage = nil
        logger.info("Starting WiFi scan...")

        do {
            // Perform scan (blocking operation)
            let networks = try interface.scanForNetworks(withSSID: nil)
            scannedNetworks = networks.map { buildNetwork(from: $0) }.sorted()
            logger.info("Scan complete: found \(networks.count) networks")
        } catch {
            logger.error("Scan failed: \(error.localizedDescription)")
            errorMessage = "Scan failed: \(error.localizedDescription)"

            // Fall back to cached results
            if let cached = interface.cachedScanResults() {
                scannedNetworks = cached.map { buildNetwork(from: $0) }.sorted()
                logger.info("Using cached results: \(cached.count) networks")
            }
        }

        isScanning = false
    }

    /// Set WiFi power state
    /// - Parameter on: Whether to turn WiFi on or off
    /// - Returns: Whether the operation succeeded
    public func setPower(_ on: Bool) async -> Bool {
        guard let interface = wifiClient.interface() else {
            errorMessage = "No WiFi interface available"
            return false
        }

        do {
            try interface.setPower(on)
            isPoweredOn = on
            logger.info("WiFi power set to \(on ? "on" : "off")")

            // Refresh state after power change
            await refresh()
            return true
        } catch {
            logger.error("Failed to set WiFi power: \(error.localizedDescription)")
            errorMessage = "Failed to set WiFi power: \(error.localizedDescription)"
            return false
        }
    }

    /// Clear signal history
    public func clearSignalHistory() {
        signalHistory.removeAll()
    }

    // MARK: - Signal History

    func addSignalSample(rssi: Int, noise: Int) {
        let sample = WiFiSignalSample(rssi: rssi, noise: noise)
        signalHistory.append(sample)

        // Trim to max count
        if signalHistory.count > maxSignalHistoryCount {
            signalHistory.removeFirst(signalHistory.count - maxSignalHistoryCount)
        }
    }
}
