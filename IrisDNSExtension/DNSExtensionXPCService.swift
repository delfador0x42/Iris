//
//  DNSExtensionXPCService.swift
//  IrisDNSExtension
//
//  XPC service for communication between the DNS proxy extension and the main app.
//

import Foundation
import Security
import os.log

/// XPC service that listens for connections from the main app.
final class DNSExtensionXPCService: NSObject, @unchecked Sendable {

    private let logger = Logger(subsystem: "com.wudan.iris.dns", category: "XPCService")
    private var listener: NSXPCListener?

    /// Reference to the DNS proxy provider
    weak var provider: DNSProxyProvider?

    static let serviceName = "99HGW2AR62.com.wudan.iris.dns.xpc"

    func start() {
        logger.info("Starting DNS XPC service on \(Self.serviceName)")

        listener = NSXPCListener(machServiceName: Self.serviceName)
        listener?.delegate = self
        listener?.resume()

        logger.info("DNS XPC service started")
    }

    func stop() {
        listener?.invalidate()
        listener = nil
        logger.info("DNS XPC service stopped")
    }
}

// MARK: - NSXPCListenerDelegate

extension DNSExtensionXPCService: NSXPCListenerDelegate {

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {

        let pid = connection.processIdentifier
        guard verifyCodeSignature(pid: pid) else {
            logger.error("DNS XPC: rejected connection from PID \(pid) — failed code signing check")
            return false
        }

        let interface = NSXPCInterface(with: DNSXPCProtocol.self)
        connection.exportedInterface = interface
        connection.exportedObject = self

        connection.invalidationHandler = { [weak self] in
            self?.logger.info("DNS XPC connection invalidated")
        }

        connection.resume()
        logger.info("DNS XPC: accepted connection from PID \(pid)")
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
}

// MARK: - DNSXPCProtocol

extension DNSExtensionXPCService: DNSXPCProtocol {

    func getStatus(reply: @escaping ([String: Any]) -> Void) {
        let status = provider?.getStatus() ?? [
            "isActive": false,
            "totalQueries": 0,
            "serverName": "Unknown"
        ]
        reply(status)
    }

    func getQueries(limit: Int, reply: @escaping ([Data]) -> Void) {
        let queries = provider?.getQueries(limit: limit) ?? []
        reply(queries)
    }

    func clearQueries(reply: @escaping (Bool) -> Void) {
        provider?.clearQueries()
        reply(true)
    }

    func setEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
        provider?.setEnabled(enabled)
        reply(true)
    }

    func isEnabled(reply: @escaping (Bool) -> Void) {
        let status = provider?.getStatus()
        reply(status?["isActive"] as? Bool ?? false)
    }

    func setServer(_ serverName: String, reply: @escaping (Bool) -> Void) {
        provider?.setServer(serverName)
        reply(true)
    }

    func getServer(reply: @escaping (String) -> Void) {
        let status = provider?.getStatus()
        reply(status?["serverName"] as? String ?? "Unknown")
    }

    func getStatistics(reply: @escaping ([String: Any]) -> Void) {
        let status = provider?.getStatus() ?? [:]
        reply(status)
    }
}
