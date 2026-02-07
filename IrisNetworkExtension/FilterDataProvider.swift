import Foundation
import NetworkExtension
import os.log

/// Network Extension filter provider for monitoring network connections
class FilterDataProvider: NEFilterDataProvider {

    // MARK: - Properties

    let logger = Logger(subsystem: "com.wudan.iris.network", category: "Filter")

    /// Active connections being tracked
    var connections: [UUID: ConnectionTracker] = [:]
    let connectionsLock = NSLock()

    /// Maps flow hash to connection ID for byte tracking
    var flowToConnection: [Int: UUID] = [:]

    /// XPC service for communicating with main app
    var xpcService: XPCService?

    /// Security rules
    var rules: [SecurityRule] = []
    let rulesLock = NSLock()

    // MARK: - Connection Tracking

    struct ConnectionTracker {
        let connection: NetworkConnection
        var bytesUp: UInt64 = 0
        var bytesDown: UInt64 = 0
        var localAddress: String
        var localPort: UInt16
        let flowId: UUID

        // HTTP tracking
        var httpRequest: ParsedHTTPRequest?
        var httpResponse: ParsedHTTPResponse?
        var requestParser: HTTPParser.StreamingRequestParser?
        var responseParser: HTTPParser.StreamingResponseParser?
        var isHTTPParsed: Bool = false
    }

    // MARK: - HTTP Data Structures (for XPC)

    struct ParsedHTTPRequest: Codable {
        let method: String
        let path: String
        let host: String?
        let contentType: String?
        let userAgent: String?
        let rawHeaders: String  // Full raw request headers
    }

    struct ParsedHTTPResponse: Codable {
        let statusCode: Int
        let reason: String
        let contentType: String?
        let contentLength: Int?
        let rawHeaders: String  // Full raw response headers
    }

    // MARK: - Lifecycle

    override init() {
        super.init()
        logger.info("FilterDataProvider initialized")
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting network filter...")

        // Start XPC service
        xpcService = XPCService()
        xpcService?.filterProvider = self
        xpcService?.start()

        // Create rule to monitor all outbound traffic
        let networkRule = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .any,
            direction: .outbound
        )

        let filterRule = NEFilterRule(networkRule: networkRule, action: .filterData)

        // Configure filter settings with rules
        let filterSettings = NEFilterSettings(rules: [filterRule], defaultAction: .filterData)

        apply(filterSettings) { error in
            if let error = error {
                self.logger.error("Failed to apply filter settings: \(error.localizedDescription)")
            } else {
                self.logger.info("Filter settings applied successfully")
            }
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping network filter, reason: \(String(describing: reason))")

        xpcService?.stop()
        xpcService = nil

        completionHandler()
    }
}
