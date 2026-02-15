import Foundation
import os.log

/// A detection alert produced by the DetectionEngine
public struct SecurityAlert: Identifiable, Sendable {
    public let id: UUID
    public let ruleId: String
    public let name: String
    public let severity: AnomalySeverity
    public let mitreId: String
    public let mitreName: String
    public let timestamp: Date
    public let processName: String
    public let processPath: String
    public let description: String
    public let events: [SecurityEvent]

    public init(
        ruleId: String, name: String,
        severity: AnomalySeverity,
        mitreId: String, mitreName: String,
        processName: String, processPath: String,
        description: String,
        events: [SecurityEvent] = []
    ) {
        self.id = UUID()
        self.ruleId = ruleId
        self.name = name
        self.severity = severity
        self.mitreId = mitreId
        self.mitreName = mitreName
        self.timestamp = Date()
        self.processName = processName
        self.processPath = processPath
        self.description = description
        self.events = events
    }
}

/// Thread-safe store for detection alerts.
/// Bounded ring buffer — oldest alerts evicted when full.
public actor AlertStore {
    public static let shared = AlertStore()

    private let logger = Logger(subsystem: "com.wudan.iris", category: "AlertStore")
    private var alerts: [SecurityAlert] = []
    private let maxAlerts = 5000

    public var count: Int { alerts.count }

    public func add(_ alert: SecurityAlert) {
        alerts.append(alert)
        if alerts.count > maxAlerts {
            alerts.removeFirst(alerts.count - maxAlerts)
        }
        logger.info("[ALERT] \(alert.severity.label): \(alert.name) — \(alert.processName)")
    }

    public func recent(_ limit: Int = 100) -> [SecurityAlert] {
        Array(alerts.suffix(limit).reversed())
    }

    public func allAlerts() -> [SecurityAlert] {
        alerts
    }

    public func alertsSince(_ date: Date) -> [SecurityAlert] {
        alerts.filter { $0.timestamp >= date }
    }

    public func clear() {
        alerts.removeAll()
    }

    public func countBySeverity() -> [AnomalySeverity: Int] {
        var counts: [AnomalySeverity: Int] = [:]
        for alert in alerts {
            counts[alert.severity, default: 0] += 1
        }
        return counts
    }
}
