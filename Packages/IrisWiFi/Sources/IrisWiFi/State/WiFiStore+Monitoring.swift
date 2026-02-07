import Foundation
import CoreWLAN
import os.log

// MARK: - Monitoring Control

@MainActor
extension WiFiStore {

    /// Start monitoring WiFi state and events
    public func startMonitoring() {
        guard !isMonitoring else {
            logger.info("WiFi monitoring already active")
            return
        }

        logger.info("Starting WiFi monitoring...")

        // Set up event delegate
        setupEventDelegate()

        // Register for events
        registerForEvents()

        // Start refresh timer
        startRefreshTimer()

        // Initial refresh
        Task {
            await refresh()
        }

        isMonitoring = true
        logger.info("WiFi monitoring started")
    }

    /// Stop monitoring WiFi state
    public func stopMonitoring() {
        logger.info("Stopping WiFi monitoring...")

        stopRefreshTimer()
        unregisterFromEvents()

        isMonitoring = false
        logger.info("WiFi monitoring stopped")
    }

    // MARK: - Data Refresh

    /// Refresh current interface state
    public func refresh() async {
        guard let interface = wifiClient.interface() else {
            errorMessage = "No WiFi interface available"
            interfaceInfo = nil
            isPoweredOn = false
            return
        }

        errorMessage = nil
        isPoweredOn = interface.powerOn()

        if isPoweredOn {
            interfaceInfo = buildInterfaceInfo(from: interface)

            // Add signal sample if connected
            if let info = interfaceInfo, info.isConnected {
                addSignalSample(rssi: info.rssi, noise: info.noise)
            }
        } else {
            interfaceInfo = buildInterfaceInfo(from: interface)
        }
    }

    // MARK: - Timer

    func startRefreshTimer() {
        stopRefreshTimer()

        refreshTimer = Timer.scheduledTimer(withTimeInterval: refreshInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refresh()
            }
        }
    }

    func stopRefreshTimer() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    // MARK: - Event Handling

    func setupEventDelegate() {
        eventDelegate = WiFiEventDelegate { [weak self] event in
            Task { @MainActor in
                self?.handleWiFiEvent(event)
            }
        }
        wifiClient.delegate = eventDelegate
    }

    func registerForEvents() {
        do {
            try wifiClient.startMonitoringEvent(with: .powerDidChange)
            try wifiClient.startMonitoringEvent(with: .ssidDidChange)
            try wifiClient.startMonitoringEvent(with: .bssidDidChange)
            try wifiClient.startMonitoringEvent(with: .linkDidChange)
            try wifiClient.startMonitoringEvent(with: .linkQualityDidChange)
            try wifiClient.startMonitoringEvent(with: .scanCacheUpdated)
            logger.info("Registered for WiFi events")
        } catch {
            logger.error("Failed to register for events: \(error.localizedDescription)")
        }
    }

    func unregisterFromEvents() {
        do {
            try wifiClient.stopMonitoringAllEvents()
            logger.info("Unregistered from WiFi events")
        } catch {
            logger.error("Failed to unregister from events: \(error.localizedDescription)")
        }
        wifiClient.delegate = nil
        eventDelegate = nil
    }

    func handleWiFiEvent(_ event: WiFiEvent) {
        logger.debug("WiFi event: \(event.rawValue)")

        Task {
            await refresh()

            // Auto-refresh scan results when cache updates
            if event == .scanCacheUpdated {
                if let interface = wifiClient.interface(),
                   let cached = interface.cachedScanResults() {
                    scannedNetworks = cached.map { buildNetwork(from: $0) }.sorted()
                }
            }
        }
    }
}
