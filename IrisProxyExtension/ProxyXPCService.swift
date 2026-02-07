//
//  ProxyXPCService.swift
//  IrisProxyExtension
//
//  XPC Service for communication between the main app and the proxy extension.
//  Core class definition with protocol, properties, and lifecycle.
//

import Foundation
import os.log

/// XPC protocol for proxy extension communication.
@objc protocol ProxyExtensionXPCProtocol {
    /// Gets the current proxy status.
    func getStatus(reply: @escaping ([String: Any]) -> Void)

    /// Gets all captured HTTP flows.
    func getFlows(reply: @escaping ([Data]) -> Void)

    /// Gets a specific flow by ID.
    func getFlow(_ flowId: String, reply: @escaping (Data?) -> Void)

    /// Clears all captured flows.
    func clearFlows(reply: @escaping (Bool) -> Void)

    /// Sets whether interception is enabled.
    func setInterceptionEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)

    /// Gets interception enabled state.
    func isInterceptionEnabled(reply: @escaping (Bool) -> Void)
}

/// XPC Service for the proxy extension.
class ProxyXPCService: NSObject {

    // MARK: - Properties

    let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "XPC")
    var listener: NSXPCListener?
    var activeConnections: [NSXPCConnection] = []
    let connectionsLock = NSLock()

    /// Reference to the proxy provider
    weak var provider: AppProxyProvider?

    /// Captured HTTP flows (stored in memory)
    var capturedFlows: [CapturedFlow] = []
    let flowsLock = NSLock()
    let maxFlows = 10000

    /// Whether interception is enabled
    var interceptionEnabled = true

    // MARK: - Service Name

    /// Gets the Mach service name from Info.plist
    static var serviceName: String {
        guard let networkExtension = Bundle.main.object(forInfoDictionaryKey: "NetworkExtension") as? [String: Any],
              let machServiceName = networkExtension["NEMachServiceName"] as? String else {
            fatalError("NEMachServiceName not found in Info.plist")
        }
        return machServiceName
    }

    // MARK: - Lifecycle

    func start() {
        logger.info("Starting proxy XPC service...")

        listener = NSXPCListener(machServiceName: Self.serviceName)
        listener?.delegate = self
        listener?.resume()

        logger.info("Proxy XPC service started on \(Self.serviceName)")
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

        logger.info("Proxy XPC service stopped")
    }
}
