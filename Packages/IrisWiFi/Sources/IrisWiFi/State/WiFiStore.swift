import Foundation
import Combine
import CoreWLAN
import os.log

/// State store for WiFi monitoring using CoreWLAN
@MainActor
public final class WiFiStore: ObservableObject {

    // MARK: - Published State

    /// Current WiFi interface information
    @Published public internal(set) var interfaceInfo: WiFiInterfaceInfo?

    /// Scanned networks (sorted by signal strength)
    @Published public internal(set) var scannedNetworks: [WiFiNetwork] = []

    /// Whether a scan is in progress
    @Published public internal(set) var isScanning = false

    /// Whether the WiFi interface is powered on
    @Published public internal(set) var isPoweredOn = false

    /// Error message if any
    @Published public internal(set) var errorMessage: String?

    /// Signal strength history for graphing
    @Published public internal(set) var signalHistory: [WiFiSignalSample] = []

    /// Whether monitoring is active
    @Published public internal(set) var isMonitoring = false

    /// WiFi preferences (JoinMode, RequireAdmin, etc.)
    @Published public internal(set) var preferences: WiFiPreferences = .default

    // MARK: - Properties

    let logger = Logger(subsystem: "com.wudan.iris", category: "WiFiStore")
    let wifiClient: CWWiFiClient
    var refreshTimer: Timer?
    var eventDelegate: WiFiEventDelegate?

    /// Refresh interval in seconds.
    /// Rationale: 1 second provides responsive signal strength updates.
    let refreshInterval: TimeInterval = 1.0

    /// Maximum number of signal samples to keep
    let maxSignalHistoryCount = 60  // 1 minute at 1 sample/second

    /// Cached MCS/NSS values (fetched less frequently than other stats)
    var cachedMCS: Int?
    var cachedNSS: Int?
    var lastMCSFetch: Date?
    let mcsFetchInterval: TimeInterval = 5.0  // Fetch MCS every 5 seconds

    // MARK: - Initialization

    public init() {
        self.wifiClient = CWWiFiClient.shared()
    }
}
