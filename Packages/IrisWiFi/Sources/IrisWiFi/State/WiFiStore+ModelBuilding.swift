import Foundation
import CoreWLAN
import os.log

// MARK: - Model Building & Type Mapping

@MainActor
extension WiFiStore {

    // MARK: - MCS/NSS Fetching

    /// Fetch MCS and NSS from system_profiler (slower but provides data not in CoreWLAN)
    func fetchMCSAndNSS() {
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

    // MARK: - Interface Info

    func buildInterfaceInfo(from interface: CWInterface) -> WiFiInterfaceInfo {
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

    // MARK: - Network Info

    func buildNetwork(from network: CWNetwork) -> WiFiNetwork {
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

    func mapChannelBand(_ band: CWChannelBand?) -> WiFiChannelBand {
        guard let band = band else { return .unknown }
        switch band {
        case .band2GHz: return .band2GHz
        case .band5GHz: return .band5GHz
        case .band6GHz: return .band6GHz
        case .bandUnknown: return .unknown
        @unknown default: return .unknown
        }
    }

    func mapChannelWidth(_ width: CWChannelWidth?) -> WiFiChannelWidth {
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

    func mapPHYMode(_ mode: CWPHYMode) -> WiFiPHYMode {
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

    func mapSecurity(_ security: CWSecurity) -> WiFiSecurityType {
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

    func mapInterfaceMode(_ mode: CWInterfaceMode) -> WiFiInterfaceMode {
        switch mode {
        case .none: return .none
        case .station: return .station
        case .IBSS: return .ibss
        case .hostAP: return .hostAP
        @unknown default: return .none
        }
    }
}
