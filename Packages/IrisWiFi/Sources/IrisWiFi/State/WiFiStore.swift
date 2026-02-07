import Foundation
import Combine
import CoreWLAN
import os.log

/// State store for WiFi monitoring using CoreWLAN
@MainActor
public final class WiFiStore: ObservableObject {

    // MARK: - Published State

    /// Current WiFi interface information
    @Published public private(set) var interfaceInfo: WiFiInterfaceInfo?

    /// Scanned networks (sorted by signal strength)
    @Published public private(set) var scannedNetworks: [WiFiNetwork] = []

    /// Whether a scan is in progress
    @Published public private(set) var isScanning = false

    /// Whether the WiFi interface is powered on
    @Published public private(set) var isPoweredOn = false

    /// Error message if any
    @Published public private(set) var errorMessage: String?

    /// Signal strength history for graphing
    @Published public private(set) var signalHistory: [WiFiSignalSample] = []

    /// Whether monitoring is active
    @Published public private(set) var isMonitoring = false

    /// WiFi preferences (JoinMode, RequireAdmin, etc.)
    @Published public private(set) var preferences: WiFiPreferences = .default

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "WiFiStore")
    private let wifiClient: CWWiFiClient
    private var refreshTimer: Timer?
    private var eventDelegate: WiFiEventDelegate?

    /// Refresh interval in seconds.
    /// Rationale: 1 second provides responsive signal strength updates.
    private let refreshInterval: TimeInterval = 1.0

    /// Maximum number of signal samples to keep
    private let maxSignalHistoryCount = 60  // 1 minute at 1 sample/second

    /// Cached MCS/NSS values (fetched less frequently than other stats)
    private var cachedMCS: Int?
    private var cachedNSS: Int?
    private var lastMCSFetch: Date?
    private let mcsFetchInterval: TimeInterval = 5.0  // Fetch MCS every 5 seconds

    // MARK: - Initialization

    public init() {
        self.wifiClient = CWWiFiClient.shared()
    }

    // MARK: - Monitoring Control

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

    // MARK: - Network Association

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

    // MARK: - Preferences

    /// Refresh preferences from system
    public func refreshPreferences() async {
        await Task.detached { [weak self] in
            guard let self = self else { return }

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
            process.arguments = ["prefs"]

            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice

            do {
                try process.run()
                process.waitUntilExit()

                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8) ?? ""

                let prefs = self.parsePreferencesOutput(output)

                await MainActor.run {
                    self.preferences = prefs
                    self.logger.debug("Refreshed WiFi preferences")
                }
            } catch {
                await MainActor.run {
                    self.logger.error("Failed to fetch preferences: \(error.localizedDescription)")
                }
            }
        }.value
    }

    /// Parse airport prefs output into WiFiPreferences
    private nonisolated func parsePreferencesOutput(_ output: String) -> WiFiPreferences {
        var prefs = WiFiPreferences.default

        for line in output.components(separatedBy: "\n") {
            let parts = line.components(separatedBy: "=")
            guard parts.count == 2 else { continue }

            let key = parts[0].trimmingCharacters(in: .whitespaces)
            let value = parts[1].trimmingCharacters(in: .whitespaces)

            switch key {
            case "JoinMode":
                prefs.joinMode = WiFiJoinMode(rawValue: value) ?? .automatic
            case "JoinModeFallback":
                prefs.joinModeFallback = WiFiJoinMode(rawValue: value) ?? .strongest
            case "RememberRecentNetworks":
                prefs.rememberRecentNetworks = (value == "YES")
            case "DisconnectOnLogout":
                prefs.disconnectOnLogout = (value == "YES")
            case "RequireAdminIBSS":
                prefs.requireAdminIBSS = (value == "YES")
            case "RequireAdminNetworkChange":
                prefs.requireAdminNetworkChange = (value == "YES")
            case "RequireAdminPowerToggle":
                prefs.requireAdminPowerToggle = (value == "YES")
            default:
                break
            }
        }

        return prefs
    }

    /// Update a WiFi preference
    /// - Parameters:
    ///   - key: The preference key (e.g., "JoinMode", "DisconnectOnLogout")
    ///   - value: The value to set
    /// - Returns: Whether the operation succeeded
    public func setPreference(key: String, value: String) async -> Bool {
        guard let interface = wifiClient.interface() else {
            errorMessage = "No WiFi interface available"
            return false
        }

        let interfaceName = interface.interfaceName ?? "en0"

        return await Task.detached { [weak self] in
            guard let self = self else { return false }

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
            process.arguments = [interfaceName, "prefs", "\(key)=\(value)"]

            do {
                try process.run()
                process.waitUntilExit()

                if process.terminationStatus == 0 {
                    await self.refreshPreferences()
                    return true
                } else {
                    await MainActor.run {
                        self.errorMessage = "Failed to set preference (may require admin)"
                    }
                    return false
                }
            } catch {
                await MainActor.run {
                    self.logger.error("Failed to set preference: \(error.localizedDescription)")
                    self.errorMessage = "Failed to set preference: \(error.localizedDescription)"
                }
                return false
            }
        }.value
    }

    // MARK: - Private Methods

    private func startRefreshTimer() {
        stopRefreshTimer()

        refreshTimer = Timer.scheduledTimer(withTimeInterval: refreshInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refresh()
            }
        }
    }

    private func stopRefreshTimer() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    private func setupEventDelegate() {
        eventDelegate = WiFiEventDelegate { [weak self] event in
            Task { @MainActor in
                self?.handleWiFiEvent(event)
            }
        }
        wifiClient.delegate = eventDelegate
    }

    private func registerForEvents() {
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

    private func unregisterFromEvents() {
        do {
            try wifiClient.stopMonitoringAllEvents()
            logger.info("Unregistered from WiFi events")
        } catch {
            logger.error("Failed to unregister from events: \(error.localizedDescription)")
        }
        wifiClient.delegate = nil
        eventDelegate = nil
    }

    private func handleWiFiEvent(_ event: WiFiEvent) {
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

    private func addSignalSample(rssi: Int, noise: Int) {
        let sample = WiFiSignalSample(rssi: rssi, noise: noise)
        signalHistory.append(sample)

        // Trim to max count
        if signalHistory.count > maxSignalHistoryCount {
            signalHistory.removeFirst(signalHistory.count - maxSignalHistoryCount)
        }
    }

    // MARK: - MCS/NSS Fetching

    /// Fetch MCS and NSS from system_profiler (slower but provides data not in CoreWLAN)
    private func fetchMCSAndNSS() {
        // Only fetch if cache is stale
        if let lastFetch = lastMCSFetch, Date().timeIntervalSince(lastFetch) < mcsFetchInterval {
            return
        }

        Task.detached { [weak self] in
            guard let self = self else { return }

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/sbin/system_profiler")
            process.arguments = ["SPAirPortDataType", "-json"]

            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice

            do {
                try process.run()
                process.waitUntilExit()

                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let airportData = json["SPAirPortDataType"] as? [[String: Any]],
                   let firstInterface = airportData.first?["spairport_airport_interfaces"] as? [[String: Any]],
                   let interface = firstInterface.first,
                   let currentNetwork = interface["spairport_current_network_information"] as? [String: Any] {

                    let mcs = currentNetwork["spairport_network_mcs"] as? Int
                    let nss = currentNetwork["spairport_network_nss"] as? Int

                    await MainActor.run {
                        self.cachedMCS = mcs
                        self.cachedNSS = nss
                        self.lastMCSFetch = Date()
                    }
                }
            } catch {
                await MainActor.run {
                    self.logger.debug("Failed to fetch MCS/NSS: \(error.localizedDescription)")
                }
            }
        }
    }

    // MARK: - Model Building

    private func buildInterfaceInfo(from interface: CWInterface) -> WiFiInterfaceInfo {
        // Trigger async MCS/NSS fetch (uses cache if recent)
        fetchMCSAndNSS()
        let channel = interface.wlanChannel()

        return WiFiInterfaceInfo(
            id: interface.interfaceName ?? "en0",
            ssid: interface.ssid(),
            bssid: interface.bssid(),
            rssi: interface.rssiValue(),
            noise: interface.noiseMeasurement(),
            channel: channel?.channelNumber ?? 0,
            channelBand: mapChannelBand(channel?.channelBand),
            channelWidth: mapChannelWidth(channel?.channelWidth),
            phyMode: mapPHYMode(interface.activePHYMode()),
            security: mapSecurity(interface.security()),
            mcsIndex: cachedMCS,
            nss: cachedNSS,
            interfaceMode: mapInterfaceMode(interface.interfaceMode()),
            transmitRate: interface.transmitRate(),
            transmitPower: interface.transmitPower(),
            hardwareAddress: interface.hardwareAddress() ?? "",
            countryCode: interface.countryCode(),
            isPoweredOn: interface.powerOn(),
            isServiceActive: interface.serviceActive()
        )
    }

    private func buildNetwork(from network: CWNetwork) -> WiFiNetwork {
        let channel = network.wlanChannel

        // Determine security type by checking supported types
        var security: WiFiSecurityType = .unknown
        for secType in [CWSecurity.wpa3Personal, .wpa3Transition, .wpa2Personal, .wpaPersonal,
                        .wpa3Enterprise, .wpa2Enterprise, .wpaEnterprise,
                        .OWE, .oweTransition, .WEP, .none] {
            if network.supportsSecurity(secType) {
                security = mapSecurity(secType)
                break
            }
        }

        return WiFiNetwork(
            id: network.bssid ?? UUID().uuidString,
            ssid: network.ssid,
            bssid: network.bssid,
            rssi: network.rssiValue,
            noise: network.noiseMeasurement,
            channel: channel?.channelNumber ?? 0,
            channelBand: mapChannelBand(channel?.channelBand),
            channelWidth: mapChannelWidth(channel?.channelWidth),
            security: security,
            isIBSS: network.ibss,
            beaconInterval: network.beaconInterval,
            countryCode: network.countryCode,
            informationElementData: network.informationElementData
        )
    }

    // MARK: - Type Mapping

    private func mapChannelBand(_ band: CWChannelBand?) -> WiFiChannelBand {
        guard let band = band else { return .unknown }
        switch band {
        case .band2GHz: return .band2GHz
        case .band5GHz: return .band5GHz
        case .band6GHz: return .band6GHz
        case .bandUnknown: return .unknown
        @unknown default: return .unknown
        }
    }

    private func mapChannelWidth(_ width: CWChannelWidth?) -> WiFiChannelWidth {
        guard let width = width else { return .unknown }
        switch width {
        case .width20MHz: return .width20MHz
        case .width40MHz: return .width40MHz
        case .width80MHz: return .width80MHz
        case .width160MHz: return .width160MHz
        case .widthUnknown: return .unknown
        @unknown default: return .unknown
        }
    }

    private func mapPHYMode(_ mode: CWPHYMode) -> WiFiPHYMode {
        switch mode {
        case .mode11a: return .mode11a
        case .mode11b: return .mode11b
        case .mode11g: return .mode11g
        case .mode11n: return .mode11n
        case .mode11ac: return .mode11ac
        case .mode11ax: return .mode11ax
        case .modeNone: return .none
        @unknown default: return .none
        }
    }

    private func mapSecurity(_ security: CWSecurity) -> WiFiSecurityType {
        switch security {
        case .none: return .none
        case .WEP: return .wep
        case .wpaPersonal: return .wpaPersonal
        case .wpaPersonalMixed: return .wpaPersonalMixed
        case .wpa2Personal: return .wpa2Personal
        case .personal: return .wpa2Personal  // Generic personal security
        case .wpa3Personal: return .wpa3Personal
        case .wpa3Transition: return .wpa3Transition
        case .dynamicWEP: return .dynamicWEP
        case .wpaEnterprise: return .wpaEnterprise
        case .wpaEnterpriseMixed: return .wpaEnterpriseMixed
        case .wpa2Enterprise: return .wpa2Enterprise
        case .enterprise: return .wpa2Enterprise  // Generic enterprise security
        case .wpa3Enterprise: return .wpa3Enterprise
        case .OWE: return .owe
        case .oweTransition: return .oweTransition
        case .unknown: return .unknown
        @unknown default: return .unknown
        }
    }

    private func mapInterfaceMode(_ mode: CWInterfaceMode) -> WiFiInterfaceMode {
        switch mode {
        case .none: return .none
        case .station: return .station
        case .IBSS: return .ibss
        case .hostAP: return .hostAP
        @unknown default: return .none
        }
    }
}

// MARK: - WiFi Event Delegate

private enum WiFiEvent: String {
    case powerDidChange
    case ssidDidChange
    case bssidDidChange
    case linkDidChange
    case linkQualityDidChange
    case scanCacheUpdated
    case modeDidChange
    case countryCodeDidChange
}

private class WiFiEventDelegate: NSObject, CWEventDelegate {
    private let handler: (WiFiEvent) -> Void

    init(handler: @escaping (WiFiEvent) -> Void) {
        self.handler = handler
    }

    func powerStateDidChangeForWiFiInterface(withName interfaceName: String) {
        handler(.powerDidChange)
    }

    func ssidDidChangeForWiFiInterface(withName interfaceName: String) {
        handler(.ssidDidChange)
    }

    func bssidDidChangeForWiFiInterface(withName interfaceName: String) {
        handler(.bssidDidChange)
    }

    func linkDidChangeForWiFiInterface(withName interfaceName: String) {
        handler(.linkDidChange)
    }

    func linkQualityDidChangeForWiFiInterface(withName interfaceName: String, rssi: Int, transmitRate: Double) {
        handler(.linkQualityDidChange)
    }

    func scanCacheUpdatedForWiFiInterface(withName interfaceName: String) {
        handler(.scanCacheUpdated)
    }

    func modeDidChangeForWiFiInterface(withName interfaceName: String) {
        handler(.modeDidChange)
    }

    func countryCodeDidChangeForWiFiInterface(withName interfaceName: String) {
        handler(.countryCodeDidChange)
    }
}
