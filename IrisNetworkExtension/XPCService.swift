import Foundation
import os.log

/// XPC Service for communication between the main app and the security extension
class XPCService: NSObject {

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris.network", category: "XPC")
    private var listener: NSXPCListener?
    private var activeConnections: [NSXPCConnection] = []
    private let connectionsLock = NSLock()

    /// Reference to the filter provider for data access
    weak var filterProvider: FilterDataProvider?

    // MARK: - Service Name

    /// Gets the Mach service name from the extension's Info.plist NEMachServiceName
    static var serviceName: String {
        guard let networkExtension = Bundle.main.object(forInfoDictionaryKey: "NetworkExtension") as? [String: Any],
              let machServiceName = networkExtension["NEMachServiceName"] as? String else {
            // Fallback - this shouldn't happen if Info.plist is configured correctly
            fatalError("NEMachServiceName not found in Info.plist")
        }
        return machServiceName
    }

    // MARK: - Lifecycle

    override init() {
        super.init()
    }

    func start() {
        logger.info("Starting XPC service...")

        // Create listener for the Mach service
        listener = NSXPCListener(machServiceName: Self.serviceName)
        listener?.delegate = self
        listener?.resume()

        logger.info("XPC service started on \(Self.serviceName)")
    }

    func stop() {
        listener?.invalidate()
        listener = nil

        connectionsLock.lock()
        for connection in activeConnections {
            connection.invalidate()
        }
        activeConnections.removeAll()
        connectionsLock.unlock()

        logger.info("XPC service stopped")
    }
}

// MARK: - NSXPCListenerDelegate

extension XPCService: NSXPCListenerDelegate {

    func listener(_ listener: NSXPCListener,
                  shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {

        logger.info("New XPC connection request")

        // Configure the connection
        newConnection.exportedInterface = NSXPCInterface(with: NetworkXPCProtocol.self)
        newConnection.exportedObject = self

        // Set up invalidation handler
        newConnection.invalidationHandler = { [weak self] in
            self?.connectionInvalidated(newConnection)
        }

        // Track the connection
        connectionsLock.lock()
        activeConnections.append(newConnection)
        connectionsLock.unlock()

        newConnection.resume()
        logger.info("XPC connection accepted")

        return true
    }

    private func connectionInvalidated(_ connection: NSXPCConnection) {
        connectionsLock.lock()
        activeConnections.removeAll { $0 === connection }
        connectionsLock.unlock()

        logger.info("XPC connection invalidated")
    }
}

// MARK: - NetworkXPCProtocol Implementation

extension XPCService: NetworkXPCProtocol {

    func getConnections(reply: @escaping ([Data]) -> Void) {
        logger.debug("XPC: getConnections")

        guard let provider = filterProvider else {
            reply([])
            return
        }

        let connections = provider.getActiveConnections()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        let data = connections.compactMap { connection -> Data? in
            try? encoder.encode(connection)
        }

        reply(data)
    }

    func getConnections(forPid pid: Int32, reply: @escaping ([Data]) -> Void) {
        logger.debug("XPC: getConnections(forPid: \(pid))")

        guard let provider = filterProvider else {
            reply([])
            return
        }

        let connections = provider.getActiveConnections().filter { $0.processId == pid }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        let data = connections.compactMap { connection -> Data? in
            try? encoder.encode(connection)
        }

        reply(data)
    }

    func getRules(reply: @escaping ([Data]) -> Void) {
        logger.debug("XPC: getRules")

        guard let provider = filterProvider else {
            reply([])
            return
        }

        let rules = provider.getRules()
        let encoder = JSONEncoder()

        let data = rules.compactMap { try? encoder.encode($0) }
        reply(data)
    }

    func addRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void) {
        logger.debug("XPC: addRule")

        guard let provider = filterProvider else {
            reply(false, "Filter provider not available")
            return
        }

        do {
            let decoder = JSONDecoder()
            let rule = try decoder.decode(SecurityRule.self, from: ruleData)
            provider.addRule(rule)
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func updateRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void) {
        logger.debug("XPC: updateRule")
        // TODO: Implement rule update
        reply(false, "Not implemented")
    }

    func removeRule(_ ruleId: String, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: removeRule(\(ruleId))")

        guard let provider = filterProvider,
              let uuid = UUID(uuidString: ruleId) else {
            reply(false)
            return
        }

        let success = provider.removeRule(id: uuid)
        reply(success)
    }

    func toggleRule(_ ruleId: String, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: toggleRule(\(ruleId))")
        // TODO: Implement rule toggle
        reply(false)
    }

    func cleanupExpiredRules(reply: @escaping (Int) -> Void) {
        logger.debug("XPC: cleanupExpiredRules")
        // TODO: Implement cleanup
        reply(0)
    }

    func getStatus(reply: @escaping ([String: Any]) -> Void) {
        logger.debug("XPC: getStatus")

        let status: [String: Any] = [
            "version": "1.0.0",
            "filterEnabled": true,
            "esEnabled": true,
            "connectionCount": filterProvider?.getActiveConnections().count ?? 0,
            "ruleCount": filterProvider?.getRules().count ?? 0
        ]

        reply(status)
    }

    func setFilteringEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: setFilteringEnabled(\(enabled))")
        // TODO: Implement filter enable/disable
        reply(true)
    }
}
