//
//  ProxyXPCService.swift
//  IrisProxyExtension
//
//  XPC Service for communication between the main app and the proxy extension.
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

    private let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "XPC")
    private var listener: NSXPCListener?
    private var activeConnections: [NSXPCConnection] = []
    private let connectionsLock = NSLock()

    /// Reference to the proxy provider
    weak var provider: AppProxyProvider?

    /// Captured HTTP flows (stored in memory)
    private var capturedFlows: [CapturedFlow] = []
    private let flowsLock = NSLock()
    private let maxFlows = 10000

    /// Whether interception is enabled
    private var interceptionEnabled = true

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

    // MARK: - Flow Management

    /// Adds a captured flow.
    func addFlow(_ flow: CapturedFlow) {
        flowsLock.lock()
        defer { flowsLock.unlock() }

        capturedFlows.append(flow)

        // Trim if over limit
        if capturedFlows.count > maxFlows {
            capturedFlows.removeFirst(capturedFlows.count - maxFlows)
        }

        // Notify connected clients
        notifyFlowUpdate(flow)
    }

    /// Updates an existing flow (e.g., when response arrives).
    func updateFlow(_ flowId: UUID, response: CapturedResponse) {
        flowsLock.lock()
        defer { flowsLock.unlock() }

        if let index = capturedFlows.firstIndex(where: { $0.id == flowId }) {
            capturedFlows[index].response = response
            notifyFlowUpdate(capturedFlows[index])
        }
    }

    /// Notifies connected clients about a flow update.
    private func notifyFlowUpdate(_ flow: CapturedFlow) {
        // TODO: Implement push notifications to connected clients
    }
}

// MARK: - NSXPCListenerDelegate

extension ProxyXPCService: NSXPCListenerDelegate {

    func listener(_ listener: NSXPCListener,
                  shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        logger.info("New XPC connection request")

        newConnection.exportedInterface = NSXPCInterface(with: ProxyExtensionXPCProtocol.self)
        newConnection.exportedObject = self

        newConnection.invalidationHandler = { [weak self] in
            self?.connectionInvalidated(newConnection)
        }

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

// MARK: - ProxyExtensionXPCProtocol

extension ProxyXPCService: ProxyExtensionXPCProtocol {

    func getStatus(reply: @escaping ([String: Any]) -> Void) {
        logger.debug("XPC: getStatus")

        var status = provider?.getStatus() ?? [:]
        status["flowCount"] = capturedFlows.count
        status["interceptionEnabled"] = interceptionEnabled

        reply(status)
    }

    func getFlows(reply: @escaping ([Data]) -> Void) {
        logger.debug("XPC: getFlows")

        flowsLock.lock()
        let flows = capturedFlows
        flowsLock.unlock()

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        let data = flows.compactMap { try? encoder.encode($0) }
        reply(data)
    }

    func getFlow(_ flowId: String, reply: @escaping (Data?) -> Void) {
        logger.debug("XPC: getFlow(\(flowId))")

        guard let uuid = UUID(uuidString: flowId) else {
            reply(nil)
            return
        }

        flowsLock.lock()
        let flow = capturedFlows.first { $0.id == uuid }
        flowsLock.unlock()

        guard let flow = flow else {
            reply(nil)
            return
        }

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        reply(try? encoder.encode(flow))
    }

    func clearFlows(reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: clearFlows")

        flowsLock.lock()
        capturedFlows.removeAll()
        flowsLock.unlock()

        reply(true)
    }

    func setInterceptionEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: setInterceptionEnabled(\(enabled))")
        interceptionEnabled = enabled
        reply(true)
    }

    func isInterceptionEnabled(reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: isInterceptionEnabled")
        reply(interceptionEnabled)
    }
}

// MARK: - Captured Flow Models

/// A captured HTTP flow (request + optional response).
struct CapturedFlow: Codable, Identifiable {
    let id: UUID
    let timestamp: Date
    let request: CapturedRequest
    var response: CapturedResponse?
    var error: String?
    let processName: String?
    let processId: Int?

    init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        request: CapturedRequest,
        response: CapturedResponse? = nil,
        error: String? = nil,
        processName: String? = nil,
        processId: Int? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.request = request
        self.response = response
        self.error = error
        self.processName = processName
        self.processId = processId
    }
}

/// A captured HTTP request.
struct CapturedRequest: Codable {
    let method: String
    let url: String
    let httpVersion: String
    let headers: [[String]]
    let bodySize: Int
    let bodyPreview: String?

    init(
        method: String,
        url: String,
        httpVersion: String = "HTTP/1.1",
        headers: [(name: String, value: String)],
        body: Data? = nil
    ) {
        self.method = method
        self.url = url
        self.httpVersion = httpVersion
        self.headers = headers.map { [$0.name, $0.value] }
        self.bodySize = body?.count ?? 0

        // Store preview of body (first 1KB)
        if let body = body, !body.isEmpty {
            let previewSize = min(body.count, 1024)
            self.bodyPreview = String(data: body.prefix(previewSize), encoding: .utf8)
        } else {
            self.bodyPreview = nil
        }
    }
}

/// A captured HTTP response.
struct CapturedResponse: Codable {
    let statusCode: Int
    let reason: String
    let httpVersion: String
    let headers: [[String]]
    let bodySize: Int
    let bodyPreview: String?
    let duration: TimeInterval

    init(
        statusCode: Int,
        reason: String,
        httpVersion: String = "HTTP/1.1",
        headers: [(name: String, value: String)],
        body: Data? = nil,
        duration: TimeInterval
    ) {
        self.statusCode = statusCode
        self.reason = reason
        self.httpVersion = httpVersion
        self.headers = headers.map { [$0.name, $0.value] }
        self.bodySize = body?.count ?? 0
        self.duration = duration

        if let body = body, !body.isEmpty {
            let previewSize = min(body.count, 1024)
            self.bodyPreview = String(data: body.prefix(previewSize), encoding: .utf8)
        } else {
            self.bodyPreview = nil
        }
    }
}
