import Foundation
import Security
import os.log

/// XPC Service for communication between the main app and the security extension
class XPCService: NSObject {

    // MARK: - Properties

    let logger = Logger(subsystem: "com.wudan.iris.network", category: "XPC")
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

        let pid = newConnection.processIdentifier
        guard verifyCodeSignature(pid: pid) else {
            logger.error("XPC: rejected connection from PID \(pid) — failed code signing check")
            return false
        }

        newConnection.exportedInterface = NSXPCInterface(with: NetworkXPCProtocol.self)
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
