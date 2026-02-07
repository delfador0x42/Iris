//
//  ProxyXPCService+FlowManagement.swift
//  IrisProxyExtension
//
//  Flow management and XPC listener delegate for ProxyXPCService.
//

import Foundation
import Security
import os.log

// MARK: - Flow Management

extension ProxyXPCService {

    /// Adds a captured flow.
    func addFlow(_ flow: ProxyCapturedFlow) {
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
    func updateFlow(_ flowId: UUID, response: ProxyCapturedResponse) {
        flowsLock.lock()
        defer { flowsLock.unlock() }

        if let index = capturedFlows.firstIndex(where: { $0.id == flowId }) {
            capturedFlows[index].response = response
            notifyFlowUpdate(capturedFlows[index])
        }
    }

    /// Notifies connected clients about a flow update.
    func notifyFlowUpdate(_ flow: ProxyCapturedFlow) {
        // TODO: Implement push notifications to connected clients
    }
}

// MARK: - NSXPCListenerDelegate

extension ProxyXPCService: NSXPCListenerDelegate {

    func listener(_ listener: NSXPCListener,
                  shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {

        let pid = newConnection.processIdentifier
        guard verifyCodeSignature(pid: pid) else {
            logger.error("XPC: rejected connection from PID \(pid) — failed code signing check")
            return false
        }

        newConnection.exportedInterface = NSXPCInterface(with: ProxyXPCProtocol.self)
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

    func connectionInvalidated(_ connection: NSXPCConnection) {
        connectionsLock.lock()
        activeConnections.removeAll { $0 === connection }
        connectionsLock.unlock()

        logger.info("XPC connection invalidated")
    }
}
