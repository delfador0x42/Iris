//
//  ESXPCService.swift
//  IrisEndpointExtension
//
//  XPC Service for communication between the main app and the endpoint security extension
//

import Foundation
import Security
import os.log

/// XPC Service for the Endpoint Security extension
class ESXPCService: NSObject {

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris.endpoint", category: "XPC")
    private var listener: NSXPCListener?
    private var activeConnections: [NSXPCConnection] = []
    private let connectionsLock = NSLock()

    /// Reference to the ES client for data access
    weak var esClient: ESClient?

    // MARK: - Service Name

    /// The Mach service name for this extension
    static let serviceName = "99HGW2AR62.com.wudan.iris.endpoint.xpc"

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

extension ESXPCService: NSXPCListenerDelegate {

    func listener(_ listener: NSXPCListener,
                  shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {

        let pid = newConnection.processIdentifier
        guard verifyCodeSignature(pid: pid) else {
            logger.error("XPC: rejected connection from PID \(pid) — failed code signing check")
            return false
        }

        newConnection.exportedInterface = NSXPCInterface(with: EndpointXPCProtocol.self)
        newConnection.exportedObject = self

        newConnection.invalidationHandler = { [weak self] in
            self?.connectionInvalidated(newConnection)
        }

        connectionsLock.lock()
        activeConnections.append(newConnection)
        connectionsLock.unlock()

        newConnection.resume()
        logger.info("XPC connection accepted from PID \(pid)")

        return true
    }

    private func verifyCodeSignature(pid: pid_t) -> Bool {
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as NSDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(), &code) == errSecSuccess,
              let guestCode = code else { return false }
        var requirement: SecRequirement?
        let reqStr = "anchor apple generic and certificate leaf[subject.OU] = \"99HGW2AR62\"" as CFString
        guard SecRequirementCreateWithString(reqStr, SecCSFlags(), &requirement) == errSecSuccess,
              let req = requirement else { return false }
        return SecCodeCheckValidity(guestCode, SecCSFlags(), req) == errSecSuccess
    }

    private func connectionInvalidated(_ connection: NSXPCConnection) {
        connectionsLock.lock()
        activeConnections.removeAll { $0 === connection }
        connectionsLock.unlock()

        logger.info("XPC connection invalidated")
    }
}

// MARK: - EndpointXPCProtocol Implementation

extension ESXPCService: EndpointXPCProtocol {

    func getProcesses(reply: @escaping ([Data]) -> Void) {
        logger.debug("XPC: getProcesses")

        guard let client = esClient else {
            reply([])
            return
        }

        let processes = client.getTrackedProcesses()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        let data = processes.compactMap { try? encoder.encode($0) }
        reply(data)
    }

    func getProcess(pid: Int32, reply: @escaping (Data?) -> Void) {
        logger.debug("XPC: getProcess(\(pid))")

        guard let client = esClient else {
            reply(nil)
            return
        }

        let processes = client.getTrackedProcesses()
        guard let process = processes.first(where: { $0.pid == pid }) else {
            reply(nil)
            return
        }

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        reply(try? encoder.encode(process))
    }

    func getRecentEvents(limit: Int, reply: @escaping ([Data]) -> Void) {
        logger.debug("XPC: getRecentEvents(\(limit))")
        // TODO: Implement event history
        reply([])
    }

    func getStatus(reply: @escaping ([String: Any]) -> Void) {
        logger.debug("XPC: getStatus")

        let status: [String: Any] = [
            "version": "1.0.0",
            "esEnabled": esClient?.isRunning ?? false,
            "processCount": esClient?.getTrackedProcesses().count ?? 0,
            "mode": "stub" // Change to "active" when ES is enabled
        ]

        reply(status)
    }

    func isEndpointSecurityAvailable(reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: isEndpointSecurityAvailable")
        reply(esClient?.isRunning ?? false)
    }
}
