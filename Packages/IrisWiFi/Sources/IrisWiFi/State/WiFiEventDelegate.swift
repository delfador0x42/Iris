import Foundation
import CoreWLAN

// MARK: - WiFi Event Types

enum WiFiEvent: String {
    case powerDidChange
    case ssidDidChange
    case bssidDidChange
    case linkDidChange
    case linkQualityDidChange
    case scanCacheUpdated
    case modeDidChange
    case countryCodeDidChange
}

// MARK: - WiFi Event Delegate

class WiFiEventDelegate: NSObject, CWEventDelegate {
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
