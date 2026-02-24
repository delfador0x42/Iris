//
//  ESXPCService.swift
//  IrisEndpointExtension
//
//  XPC Service for communication between the main app and the endpoint security extension
//

import EndpointSecurity
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
        logger.info("[XPC] Starting XPC listener on \(Self.serviceName)...")

        // Create listener for the Mach service
        listener = NSXPCListener(machServiceName: Self.serviceName)
        listener?.delegate = self
        listener?.resume()

        logger.info("[XPC] XPC listener RESUMED — ready to accept connections")
    }

    func stop() {
        listener?.invalidate()
        listener = nil

        connectionsLock.lock()
        let snapshot = activeConnections
        activeConnections.removeAll()
        connectionsLock.unlock()
        for connection in snapshot {
            connection.invalidate()
        }

        logger.info("XPC service stopped")
    }
}

// MARK: - NSXPCListenerDelegate

extension ESXPCService: NSXPCListenerDelegate {

    func listener(_ listener: NSXPCListener,
                  shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {

        let pid = newConnection.processIdentifier
        logger.info("[XPC] New connection request from PID \(pid)")

        guard verifyCodeSignature(pid: pid) else {
            logger.error("[XPC] REJECTED connection from PID \(pid) — code signing verification FAILED")
            return false
        }

        // Mute the connecting app so we don't flood events with Iris watching itself
        muteConnectingProcess(pid)

        newConnection.exportedInterface = NSXPCInterface(with: EndpointXPCProtocol.self)
        newConnection.exportedObject = self

        newConnection.invalidationHandler = { [weak self] in
            self?.connectionInvalidated(newConnection)
        }

        connectionsLock.lock()
        defer { connectionsLock.unlock() }
        activeConnections.append(newConnection)
        let count = activeConnections.count

        newConnection.resume()
        logger.info("[XPC] ACCEPTED + muted PID \(pid) (total active: \(count))")

        return true
    }

    private func verifyCodeSignature(pid: pid_t) -> Bool {
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as NSDictionary
        let copyResult = SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(), &code)
        guard copyResult == errSecSuccess, let guestCode = code else {
            logger.error("[XPC] SecCodeCopyGuestWithAttributes FAILED for PID \(pid): \(copyResult)")
            return false
        }
        var requirement: SecRequirement?
        let reqStr = "anchor apple generic and certificate leaf[subject.OU] = \"99HGW2AR62\"" as CFString
        guard SecRequirementCreateWithString(reqStr, SecCSFlags(), &requirement) == errSecSuccess,
              let req = requirement else {
            logger.error("[XPC] SecRequirementCreateWithString FAILED")
            return false
        }
        let checkResult = SecCodeCheckValidity(guestCode, SecCSFlags(), req)
        if checkResult != errSecSuccess {
            logger.error("[XPC] SecCodeCheckValidity FAILED for PID \(pid): \(checkResult)")
        }
        return checkResult == errSecSuccess
    }

    /// Mute a connecting process at the ES level to eliminate self-monitoring noise.
    /// Uses audit_token_t from the PID to call es_mute_process.
    private func muteConnectingProcess(_ pid: pid_t) {
        guard let client = esClient?.client else {
            logger.warning("[XPC] Cannot mute PID \(pid) — no ES client")
            return
        }
        var token = audit_token_t()
        var size = UInt32(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        var taskPort: mach_port_t = 0
        let kr = task_for_pid(mach_task_self_, pid, &taskPort)
        guard kr == KERN_SUCCESS else {
            logger.warning("[XPC] task_for_pid failed for PID \(pid): \(kr) — muting by path instead")
            // Fallback: mute by path (less precise but still effective)
            let pathBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
            defer { pathBuf.deallocate() }
            let pathLen = proc_pidpath(pid, pathBuf, UInt32(MAXPATHLEN))
            if pathLen > 0 {
                let path = String(cString: pathBuf)
                let result = es_mute_path_literal(client, path)
                logger.info("[XPC] Muted path \(path) for PID \(pid): \(result == ES_RETURN_SUCCESS ? "OK" : "FAIL")")
            }
            return
        }
        defer { mach_port_deallocate(mach_task_self_, taskPort) }
        let tkr = task_info(
            taskPort, task_flavor_t(TASK_AUDIT_TOKEN),
            withUnsafeMutablePointer(to: &token) {
                $0.withMemoryRebound(to: integer_t.self, capacity: Int(size)) { $0 }
            }, &size)
        guard tkr == KERN_SUCCESS else {
            logger.warning("[XPC] task_info failed for PID \(pid): \(tkr)")
            return
        }
        let result = es_mute_process(client, &token)
        logger.info("[XPC] Muted PID \(pid) via audit_token: \(result == ES_RETURN_SUCCESS ? "OK" : "FAIL")")
    }

    private func connectionInvalidated(_ connection: NSXPCConnection) {
        let pid = connection.processIdentifier
        connectionsLock.lock()
        defer { connectionsLock.unlock() }
        activeConnections.removeAll { $0 === connection }
        let count = activeConnections.count

        logger.info("[XPC] Connection from PID \(pid) invalidated (remaining: \(count))")
    }
}

// MARK: - EndpointXPCProtocol Implementation

extension ESXPCService: EndpointXPCProtocol {

    func getProcesses(reply: @escaping ([Data]) -> Void) {
        guard let client = esClient else {
            logger.warning("[XPC] getProcesses — no esClient available")
            reply([])
            return
        }

        let processes = client.getTrackedProcesses()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        let data = processes.compactMap { try? encoder.encode($0) }
        logger.info("[XPC] getProcesses → \(processes.count) tracked, \(data.count) encoded")
        reply(data)
    }

    func getRecentEvents(limit: Int, reply: @escaping ([Data]) -> Void) {
        guard let client = esClient else {
            logger.warning("[XPC] getRecentEvents — no esClient available")
            reply([])
            return
        }

        let events = client.getRecentEvents(limit: limit)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        let data = events.compactMap { try? encoder.encode($0) }
        logger.info("[XPC] getRecentEvents(\(limit)) → \(events.count) events, \(data.count) encoded")
        reply(data)
    }

    func getSecurityEventsSince(_ sinceSeq: UInt64, limit: Int, reply: @escaping (UInt64, [Data]) -> Void) {
        guard let client = esClient else {
            logger.warning("[XPC] getSecurityEventsSince — no esClient available")
            reply(0, [])
            return
        }

        let (maxSeq, events) = client.getSecurityEventsSince(sinceSeq, limit: limit)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        let data = events.compactMap { try? encoder.encode($0) }
        logger.info("[XPC] getSecurityEventsSince(\(sinceSeq)) → seq=\(maxSeq) events=\(data.count)")
        reply(maxSeq, data)
    }

    func getStatus(reply: @escaping ([String: Any]) -> Void) {
        let isRunning = esClient?.isRunning ?? false
        let processCount = esClient?.processCount ?? 0
        let startupError = esClient?.startupError

        logger.info("[XPC] getStatus → esEnabled=\(isRunning) processCount=\(processCount) error=\(startupError ?? "none")")

        var status: [String: Any] = [
            "version": "1.0.0",
            "esEnabled": isRunning,
            "processCount": processCount,
            "mode": isRunning ? "active" : "inactive",
            "enforcementEnabled": !ExecPolicy.auditMode,
        ]

        if let error = startupError {
            status["esError"] = error
        }

        reply(status)
    }

    func updateBlocklists(paths: [String], teamIds: [String], signingIds: [String],
                          reply: @escaping (Bool) -> Void) {
        ExecPolicy.updateBlocklists(
            paths: Set(paths), teamIds: Set(teamIds), signingIds: Set(signingIds)
        )
        logger.info("[XPC] updateBlocklists → \(paths.count) paths, \(teamIds.count) teams, \(signingIds.count) sigIDs")
        reply(true)
    }

    func setEnforcementMode(_ enforce: Bool, reply: @escaping (Bool) -> Void) {
        ExecPolicy.auditMode = !enforce
        logger.info("[XPC] setEnforcementMode → enforce=\(enforce) (auditMode=\(!enforce))")
        reply(true)
    }
}
