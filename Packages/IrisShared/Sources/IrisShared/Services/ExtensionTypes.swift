import Foundation

// MARK: - Extension Type

/// Types of system extensions managed by Iris
public enum ExtensionType: CaseIterable {
    case network
    case endpoint
    case dns

    public var bundleIdentifier: String {
        switch self {
        case .network: return "com.wudan.iris.network.extension"
        case .endpoint: return "com.wudan.iris.endpoint.extension"
        case .dns: return "com.wudan.iris.dns.extension"
        }
    }

    public var displayName: String {
        switch self {
        case .network: return "Network Filter"
        case .endpoint: return "Process Monitor"
        case .dns: return "DNS Proxy"
        }
    }

    public var description: String {
        switch self {
        case .network: return "Monitors and filters network connections"
        case .endpoint: return "Monitors process execution"
        case .dns: return "Encrypts DNS queries via DoH"
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

// MARK: - Filter State

/// State of the network filter
public enum FilterState: Equatable {
    case unknown
    case disabled
    case enabled
    case configuring

    public var description: String {
        switch self {
        case .unknown: return "Unknown"
        case .disabled: return "Disabled"
        case .enabled: return "Enabled"
        case .configuring: return "Configuring..."
        }
    }
}
