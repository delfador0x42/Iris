//
//  ProxyXPCService+FlowManagement.swift
//  IrisProxyExtension
//
//  Flow management and XPC listener delegate for ProxyXPCService.
//

import Foundation
import os.log

// MARK: - Flow Management

extension ProxyXPCService {

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
    func notifyFlowUpdate(_ flow: CapturedFlow) {
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

    func connectionInvalidated(_ connection: NSXPCConnection) {
        connectionsLock.lock()
        activeConnections.removeAll { $0 === connection }
        connectionsLock.unlock()

        logger.info("XPC connection invalidated")
    }
}
