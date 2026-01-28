import Foundation

/// Represents a firewall rule for allowing/blocking network connections
public struct SecurityRule: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let processPath: String?
    public let signingId: String?
    public let remoteAddress: String?
    public let remotePort: String?
    public let `protocol`: NetworkConnection.NetworkProtocol?
    public let action: RuleAction
    public let scope: RuleScope
    public let createdAt: Date
    public var isEnabled: Bool
    public var expiresAt: Date?

    public init(
        id: UUID = UUID(),
        processPath: String? = nil,
        signingId: String? = nil,
        remoteAddress: String? = nil,
        remotePort: String? = nil,
        protocol: NetworkConnection.NetworkProtocol? = nil,
        action: RuleAction,
        scope: RuleScope,
        createdAt: Date = Date(),
        isEnabled: Bool = true,
        expiresAt: Date? = nil
    ) {
        self.id = id
        self.processPath = processPath
        self.signingId = signingId
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.protocol = `protocol`
        self.action = action
        self.scope = scope
        self.createdAt = createdAt
        self.isEnabled = isEnabled
        self.expiresAt = expiresAt
    }

    /// Rule action (allow or block)
    public enum RuleAction: String, Codable, Sendable {
        case allow
        case block

        public var displayName: String {
            switch self {
            case .allow: return "Allow"
            case .block: return "Block"
            }
        }
    }

    /// Rule scope (process-wide or specific endpoint)
    public enum RuleScope: String, Codable, Sendable {
        case process   // Applies to all connections from the process
        case endpoint  // Applies to specific remote endpoint

        public var displayName: String {
            switch self {
            case .process: return "All Connections"
            case .endpoint: return "Specific Endpoint"
            }
        }
    }

    /// Rule lookup key (signing ID preferred, falls back to path)
    public var key: String {
        signingId ?? processPath ?? "unknown"
    }

    /// Whether the rule has expired
    public var isExpired: Bool {
        guard let expiresAt = expiresAt else { return false }
        return Date() > expiresAt
    }

    /// Whether the rule is currently active
    public var isActive: Bool {
        isEnabled && !isExpired
    }

    /// Human-readable rule description
    public var ruleDescription: String {
        var parts: [String] = []

        parts.append(action.displayName)

        if let path = processPath {
            let name = URL(fileURLWithPath: path).lastPathComponent
            parts.append("from \(name)")
        }

        if scope == .endpoint {
            if let address = remoteAddress, let port = remotePort {
                parts.append("to \(address):\(port)")
            } else if let address = remoteAddress {
                parts.append("to \(address)")
            }
        }

        return parts.joined(separator: " ")
    }
}

// MARK: - Rule Matching

extension SecurityRule {
    /// Check if this rule matches a given connection
    public func matches(connection: NetworkConnection) -> Bool {
        // Rule must be active
        guard isActive else { return false }

        // Check process match (by signing ID or path)
        if signingId != nil {
            // TODO: Match by signing ID when connection has signing info
            // For now, fall back to path matching
            if let processPath = processPath, processPath != connection.processPath {
                return false
            }
        } else if let processPath = processPath {
            if processPath != connection.processPath {
                return false
            }
        }

        // For endpoint scope, check remote address/port
        if scope == .endpoint {
            if let remoteAddress = remoteAddress {
                // Support wildcard "*" or regex matching
                if remoteAddress != "*" && remoteAddress != connection.remoteAddress {
                    // Check if it's a hostname match
                    if let hostname = connection.remoteHostname, hostname != remoteAddress {
                        return false
                    } else if connection.remoteHostname == nil {
                        return false
                    }
                }
            }

            if let remotePort = remotePort, remotePort != "*" {
                if let port = UInt16(remotePort), port != connection.remotePort {
                    return false
                }
            }

            if let proto = self.protocol, proto != connection.protocol {
                return false
            }
        }

        return true
    }
}

// MARK: - Rule Creation Helpers

extension SecurityRule {
    /// Create a rule to allow all connections from a process
    public static func allowProcess(path: String, signingId: String? = nil) -> SecurityRule {
        SecurityRule(
            processPath: path,
            signingId: signingId,
            action: .allow,
            scope: .process
        )
    }

    /// Create a rule to block all connections from a process
    public static func blockProcess(path: String, signingId: String? = nil) -> SecurityRule {
        SecurityRule(
            processPath: path,
            signingId: signingId,
            action: .block,
            scope: .process
        )
    }

    /// Create a rule for a specific endpoint
    public static func forEndpoint(
        processPath: String,
        remoteAddress: String,
        remotePort: String = "*",
        action: RuleAction
    ) -> SecurityRule {
        SecurityRule(
            processPath: processPath,
            remoteAddress: remoteAddress,
            remotePort: remotePort,
            action: action,
            scope: .endpoint
        )
    }

    /// Create a temporary rule that expires
    public static func temporary(
        processPath: String,
        action: RuleAction,
        duration: TimeInterval
    ) -> SecurityRule {
        SecurityRule(
            processPath: processPath,
            action: action,
            scope: .process,
            expiresAt: Date().addingTimeInterval(duration)
        )
    }
}
