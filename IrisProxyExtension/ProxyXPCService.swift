//
//  ProxyXPCService.swift
//  IrisProxyExtension
//
//  XPC Service for communication between the main app and the proxy extension.
//  Core class definition with protocol, properties, and lifecycle.
//

import Foundation
import os.log

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
    var capturedFlows: [ProxyCapturedFlow] = []
    let flowsLock = NSLock()
    let maxFlows = 10000

    /// Whether interception is enabled (guarded by interceptionLock)
    private var _interceptionEnabled = true
    let interceptionLock = NSLock()

    var interceptionEnabled: Bool {
        get {
            interceptionLock.lock()
            defer { interceptionLock.unlock() }
            return _interceptionEnabled
        }
        set {
            interceptionLock.lock()
            _interceptionEnabled = newValue
            interceptionLock.unlock()
        }
    }

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
