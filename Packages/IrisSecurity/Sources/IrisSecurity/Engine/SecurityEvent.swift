import Foundation

/// Source system that produced the event
public enum SecurityEventSource: String, Sendable, Codable {
    case endpoint   // ES extension (process, file, privilege, injection)
    case network    // Network filter extension (TCP/UDP connections)
    case dns        // DNS proxy extension (queries/responses)
    case proxy      // Transparent proxy (HTTPS inspection)
}

/// Unified event model consumed by the DetectionEngine.
/// All event sources (ES, Network, DNS) normalize into this format.
public struct SecurityEvent: Identifiable, Sendable {
    public let id: UUID
    public let source: SecurityEventSource
    public let timestamp: Date
    public let eventType: String       // "file_open", "connection", "dns_query", etc.
    public let processName: String
    public let processPath: String
    public let pid: Int32
    public let signingId: String?
    public let isAppleSigned: Bool
    public let fields: [String: String] // event-specific key-value pairs

    public init(
        source: SecurityEventSource,
        timestamp: Date = Date(),
        eventType: String,
        processName: String,
        processPath: String,
        pid: Int32,
        signingId: String? = nil,
        isAppleSigned: Bool = false,
        fields: [String: String] = [:]
    ) {
        self.id = UUID()
        self.source = source
        self.timestamp = timestamp
        self.eventType = eventType
        self.processName = processName
        self.processPath = processPath
        self.pid = pid
        self.signingId = signingId
        self.isAppleSigned = isAppleSigned
        self.fields = fields
    }
}
