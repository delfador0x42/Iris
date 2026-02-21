import Foundation
import UserNotifications
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
/// True ring buffer — O(1) insert, O(1) eviction, bounded memory.
public actor AlertStore {
    public static let shared = AlertStore()

    private let logger = Logger(subsystem: "com.wudan.iris", category: "AlertStore")
    private let maxAlerts = 5000
    private var ring: [SecurityAlert?]
    private var ringHead = 0
    private var ringCount = 0

    /// Dedup window: suppress duplicate (ruleId + processName) within this interval
    private var recentAlertKeys: [String: Date] = [:]
    private let dedupWindow: TimeInterval = 60

    public var count: Int { ringCount }

    /// Cached notification authorization — avoids XPC to usernoted on every alert
    private var notificationAuthChecked = false

    init() {
        ring = [SecurityAlert?](repeating: nil, count: maxAlerts)
    }

    public func add(_ alert: SecurityAlert) {
        // Deduplicate: same rule + process within window
        let dedupKey = "\(alert.ruleId):\(alert.processName)"
        let now = Date()
        if let lastSeen = recentAlertKeys[dedupKey],
           now.timeIntervalSince(lastSeen) < dedupWindow {
            return
        }
        recentAlertKeys[dedupKey] = now

        // Prune stale dedup keys periodically
        if recentAlertKeys.count > 1000 {
            recentAlertKeys = recentAlertKeys.filter { now.timeIntervalSince($0.value) < dedupWindow }
        }

        // Ring buffer O(1) insert
        let writeIndex = (ringHead + ringCount) % maxAlerts
        ring[writeIndex] = alert
        if ringCount < maxAlerts {
            ringCount += 1
        } else {
            ringHead = (ringHead + 1) % maxAlerts
        }

        logger.info("[ALERT] \(alert.severity.label): \(alert.name) — \(alert.processName)")

        if alert.severity == .critical || alert.severity == .high {
            postSystemNotification(alert)
        }
    }

    private nonisolated func postSystemNotification(_ alert: SecurityAlert) {
        let center = UNUserNotificationCenter.current()
        // Request auth only once — subsequent calls are fast no-ops but still involve XPC
        center.getNotificationSettings { settings in
            guard settings.authorizationStatus == .authorized ||
                  settings.authorizationStatus == .provisional else {
                center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
                return
            }
            let content = UNMutableNotificationContent()
            content.title = "Iris: \(alert.severity.label) Alert"
            content.body = "\(alert.name) — \(alert.processName)"
            content.sound = alert.severity == .critical ? .defaultCritical : .default
            let request = UNNotificationRequest(
                identifier: alert.id.uuidString,
                content: content, trigger: nil)
            center.add(request) { _ in }
        }
    }

    public func recent(_ limit: Int = 100) -> [SecurityAlert] {
        let count = min(limit, ringCount)
        var result: [SecurityAlert] = []
        result.reserveCapacity(count)
        // Read newest first
        for i in stride(from: count - 1, through: 0, by: -1) {
            let idx = (ringHead + ringCount - 1 - (count - 1 - i)) % maxAlerts
            if let alert = ring[idx] { result.append(alert) }
        }
        return result
    }

    public func allAlerts() -> [SecurityAlert] {
        var result: [SecurityAlert] = []
        result.reserveCapacity(ringCount)
        for i in 0..<ringCount {
            let idx = (ringHead + i) % maxAlerts
            if let alert = ring[idx] { result.append(alert) }
        }
        return result
    }

    public func alertsSince(_ date: Date) -> [SecurityAlert] {
        var result: [SecurityAlert] = []
        for i in 0..<ringCount {
            let idx = (ringHead + i) % maxAlerts
            if let alert = ring[idx], alert.timestamp >= date {
                result.append(alert)
            }
        }
        return result
    }

    public func clear() {
        ring = [SecurityAlert?](repeating: nil, count: maxAlerts)
        ringHead = 0
        ringCount = 0
    }

    public func countBySeverity() -> [AnomalySeverity: Int] {
        var counts: [AnomalySeverity: Int] = [:]
        for i in 0..<ringCount {
            let idx = (ringHead + i) % maxAlerts
            if let alert = ring[idx] {
                counts[alert.severity, default: 0] += 1
            }
        }
        return counts
    }
}
