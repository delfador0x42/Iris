import Foundation

// MARK: - Extension Type

/// Types of system extensions managed by Iris.
/// Two extensions: Endpoint (EndpointSecurity) and Network (unified proxy).
public enum ExtensionType: CaseIterable {
    case endpoint   // EndpointSecurity — process monitoring, AUTH events
    case network    // Unified network — proxy + DNS + firewall rules

    public var bundleIdentifier: String {
        switch self {
        case .endpoint: return "com.wudan.iris.endpoint.extension"
        case .network: return "com.wudan.iris.proxy.extension"
        }
    }

    /// Resolve extension type from bundle identifier (used in delegate callbacks)
    public init?(bundleIdentifier: String) {
        switch bundleIdentifier {
        case "com.wudan.iris.endpoint.extension": self = .endpoint
        case "com.wudan.iris.proxy.extension": self = .network
        default: return nil
        }
    }

    public var displayName: String {
        switch self {
        case .endpoint: return "Process Monitor"
        case .network: return "Network Monitor"
        }
    }

    public var description: String {
        switch self {
        case .endpoint: return "Monitors process execution and file system events"
        case .network: return "Monitors network traffic, encrypts DNS, and inspects HTTPS"
        }
    }
}

// MARK: - Extension State

/// State of a system extension
public enum ExtensionState: Equatable {
    case unknown
    case notInstalled
    case installing
    case needsUserApproval
    case installed
    case failed(String)

    public var description: String {
        switch self {
        case .unknown: return "Unknown"
        case .notInstalled: return "Not Installed"
        case .installing: return "Installing..."
        case .needsUserApproval: return "Needs Approval"
        case .installed: return "Installed"
        case .failed(let error): return "Failed: \(error)"
        }
    }

    public var isReady: Bool {
        self == .installed
    }
}
