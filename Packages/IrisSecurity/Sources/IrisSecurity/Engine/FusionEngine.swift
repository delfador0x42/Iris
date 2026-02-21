import Foundation

// MARK: - Kill Chain (MITRE ATT&CK Tactics)

/// Cyber Kill Chain stages aligned with MITRE ATT&CK tactics.
/// Used for multi-domain evidence correlation and campaign detection.
public enum KillChainStage: Int, Sendable, Codable, Comparable, CaseIterable {
    case reconnaissance = 0
    case initialAccess = 1
    case execution = 2
    case persistence = 3
    case privilegeEscalation = 4
    case defenseEvasion = 5
    case credentialAccess = 6
    case discovery = 7
    case lateralMovement = 8
    case collection = 9
    case c2 = 10
    case exfiltration = 11
    case impact = 12

    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var name: String {
        switch self {
        case .reconnaissance: "Reconnaissance"
        case .initialAccess: "Initial Access"
        case .execution: "Execution"
        case .persistence: "Persistence"
        case .privilegeEscalation: "Privilege Escalation"
        case .defenseEvasion: "Defense Evasion"
        case .credentialAccess: "Credential Access"
        case .discovery: "Discovery"
        case .lateralMovement: "Lateral Movement"
        case .collection: "Collection"
        case .c2: "Command & Control"
        case .exfiltration: "Exfiltration"
        case .impact: "Impact"
        }
    }
}

// MARK: - Evidence

/// A normalized piece of evidence from any detection source.
public struct ThreatEvidence: Sendable {
    public let source: EvidenceSource
    public let processPath: String
    public let signingId: String?
    public let networkPeer: String?
    public let technique: String
    public let severity: AnomalySeverity
    public let mitreId: String?
    public let stage: KillChainStage
    public let timestamp: Date
    public let detail: String
}

public enum EvidenceSource: String, Sendable {
    case scanner
    case realtime
    case correlation
}

// MARK: - Entity

/// An entity with aggregated cross-domain evidence.
public struct ThreatEntity: Identifiable, Sendable {
    public let id: UUID
    public let entityType: EntityType
    public let key: String
    public let evidence: [ThreatEvidence]
    public let stages: Set<KillChainStage>
    public let domainCount: Int
    public let threatScore: Double
    public let maxSeverity: AnomalySeverity

    public enum EntityType: String, Sendable {
        case process
        case signingId
        case networkPeer
    }
}

// MARK: - Campaign

/// An attack campaign spanning multiple entities and kill chain stages.
public struct CampaignDetection: Identifiable, Sendable {
    public let id: UUID
    public let name: String
    public let entities: [ThreatEntity]
    public let killChain: [KillChainStage]
    public let confidence: Double
    public let severity: AnomalySeverity
    public let description: String
}

// MARK: - Result

public struct FusionResult: Sendable {
    public let entities: [ThreatEntity]
    public let campaigns: [CampaignDetection]
    public let timestamp: Date

    public static let empty = FusionResult(entities: [], campaigns: [], timestamp: Date())
}

// MARK: - Engine

/// Cross-domain threat intelligence fusion.
/// Bridges batch scanner findings with real-time alerts into unified threat
/// assessment with kill chain mapping, cross-domain scoring, and campaign detection.
public struct FusionEngine: Sendable {

    /// Fuse scanner results + real-time alerts into cross-domain threat assessment.
    public static func fuse(
        scannerResults: [ScannerResult],
        correlations: [CorrelationEngine.Correlation],
        recentAlerts: [SecurityAlert]
    ) -> FusionResult {
        var evidence: [ThreatEvidence] = []
        evidence.reserveCapacity(scannerResults.count * 4 + recentAlerts.count)

        // Scanner anomalies → evidence
        for r in scannerResults {
            for a in r.anomalies {
                evidence.append(ThreatEvidence(
                    source: .scanner, processPath: a.processPath,
                    signingId: nil, networkPeer: extractPeer(a),
                    technique: a.technique, severity: a.severity,
                    mitreId: a.mitreID,
                    stage: classify(mitre: a.mitreID, scanner: r.id, technique: a.technique),
                    timestamp: a.timestamp, detail: a.description))
            }
        }

        // Correlation chain findings → evidence
        for c in correlations {
            for a in c.anomalies {
                evidence.append(ThreatEvidence(
                    source: .correlation, processPath: a.processPath,
                    signingId: nil, networkPeer: nil,
                    technique: c.name, severity: c.severity,
                    mitreId: a.mitreID,
                    stage: classify(mitre: a.mitreID, scanner: a.scannerId, technique: a.technique),
                    timestamp: a.timestamp, detail: c.description))
            }
        }

        // Real-time alerts → evidence
        for alert in recentAlerts {
            let ev0 = alert.events.first
            evidence.append(ThreatEvidence(
                source: .realtime, processPath: alert.processPath,
                signingId: ev0?.signingId,
                networkPeer: ev0.flatMap { $0.fields["remote_host"] ?? $0.fields["remote_address"] },
                technique: alert.name, severity: alert.severity,
                mitreId: alert.mitreId,
                stage: classify(mitre: alert.mitreId, scanner: alert.ruleId, technique: alert.name),
                timestamp: alert.timestamp, detail: alert.description))
        }

        guard !evidence.isEmpty else { return .empty }

        // Group by entity type and score
        var entities: [ThreatEntity] = []
        for (path, ev) in group(evidence, by: \.processPath) where !path.isEmpty {
            entities.append(score(type: .process, key: path, evidence: ev))
        }
        for (sig, ev) in group(evidence.filter { $0.signingId != nil }, by: { $0.signingId! }) where ev.count >= 2 {
            entities.append(score(type: .signingId, key: sig, evidence: ev))
        }
        for (peer, ev) in group(evidence.filter { $0.networkPeer != nil }, by: { $0.networkPeer! }) where ev.count >= 2 {
            entities.append(score(type: .networkPeer, key: peer, evidence: ev))
        }
        entities.sort { $0.threatScore > $1.threatScore }

        return FusionResult(entities: entities, campaigns: detectCampaigns(entities), timestamp: Date())
    }

    // MARK: - Scoring

    private static func score(
        type: ThreatEntity.EntityType, key: String, evidence: [ThreatEvidence]
    ) -> ThreatEntity {
        let stages = Set(evidence.map(\.stage))
        let domains = Set(evidence.map(\.source))
        let maxSev = evidence.map(\.severity).max() ?? .low

        // Base: severity-weighted evidence count
        var s: Double = 0
        for e in evidence {
            switch e.severity {
            case .critical: s += 0.35
            case .high:     s += 0.22
            case .medium:   s += 0.12
            case .low:      s += 0.04
            }
        }
        // Cross-domain multiplier: evidence from N sources → 1.0 + 0.3*(N-1)
        s *= 1.0 + 0.3 * Double(domains.count - 1)
        // Kill chain breadth: covering N stages → 1.0 + 0.2*(N-1)
        s *= 1.0 + 0.2 * Double(stages.count - 1)

        return ThreatEntity(
            id: UUID(), entityType: type, key: key, evidence: evidence,
            stages: stages, domainCount: domains.count,
            threatScore: min(1.0, s), maxSeverity: maxSev)
    }

    // MARK: - Campaign Detection

    private static func detectCampaigns(_ entities: [ThreatEntity]) -> [CampaignDetection] {
        let candidates = entities.filter { $0.entityType == .process && $0.stages.count >= 2 }
        guard candidates.count >= 2 else { return [] }

        var campaigns: [CampaignDetection] = []
        var used = Set<UUID>()
        let window: TimeInterval = 3600 // 1-hour clustering window

        for (i, entity) in candidates.enumerated() {
            guard !used.contains(entity.id) else { continue }
            let times = entity.evidence.map(\.timestamp)
            guard let tMin = times.min(), let tMax = times.max() else { continue }

            var cluster = [entity]
            var stages = entity.stages

            for j in (i + 1)..<candidates.count {
                let other = candidates[j]
                guard !used.contains(other.id) else { continue }
                let otherTimes = other.evidence.map(\.timestamp)
                guard let oMin = otherTimes.min(), let oMax = otherTimes.max() else { continue }

                // Temporal overlap within window
                let gapStart = max(tMin.timeIntervalSince1970 - window, oMin.timeIntervalSince1970 - window)
                let gapEnd = min(tMax.timeIntervalSince1970 + window, oMax.timeIntervalSince1970 + window)
                if gapStart <= gapEnd {
                    cluster.append(other)
                    stages.formUnion(other.stages)
                }
            }

            // Campaign: 2+ entities covering 3+ kill chain stages
            guard cluster.count >= 2, stages.count >= 3 else { continue }
            let sorted = stages.sorted()
            let maxSev = cluster.map(\.maxSeverity).max() ?? .high
            let names = cluster.map { ($0.key as NSString).lastPathComponent }

            campaigns.append(CampaignDetection(
                id: UUID(),
                name: campaignName(sorted),
                entities: cluster,
                killChain: sorted,
                confidence: campaignConfidence(cluster, stages),
                severity: maxSev >= .high ? .critical : .high,
                description: "\(names.joined(separator: ", ")) \u{2014} \(sorted.map(\.name).joined(separator: " \u{2192} "))"))
            for e in cluster { used.insert(e.id) }
        }
        return campaigns
    }

    private static func campaignName(_ stages: [KillChainStage]) -> String {
        let s = Set(stages)
        if s.contains(.credentialAccess) && s.contains(.exfiltration) { return "Data Theft Campaign" }
        if s.contains(.persistence) && s.contains(.c2) { return "Implant Campaign" }
        if s.contains(.impact) { return "Destructive Campaign" }
        if s.contains(.privilegeEscalation) && s.contains(.defenseEvasion) { return "Evasion Campaign" }
        if stages.count >= 4 { return "Advanced Persistent Threat" }
        return "Multi-Stage Attack"
    }

    private static func campaignConfidence(_ cluster: [ThreatEntity], _ stages: Set<KillChainStage>) -> Double {
        var c = 0.3
        c += min(0.2, Double(cluster.count) * 0.1)
        c += min(0.3, Double(stages.count) * 0.05)
        c += min(0.2, Double(cluster.reduce(0) { $0 + $1.evidence.count }) * 0.02)
        return min(1.0, c)
    }

    // MARK: - Kill Chain Classification

    private static func classify(mitre: String?, scanner: String, technique: String) -> KillChainStage {
        if let id = mitre, let stage = mitreMap[String(id.prefix(5))] { return stage }
        if let stage = scannerMap[scanner] { return stage }
        return classifyByKeyword(technique)
    }

    private static func classifyByKeyword(_ t: String) -> KillChainStage {
        let l = t.lowercased()
        if l.contains("persist") || l.contains("launch") || l.contains("cron") { return .persistence }
        if l.contains("inject") || l.contains("dylib") || l.contains("thread") { return .execution }
        if l.contains("credential") || l.contains("keychain") || l.contains("password") { return .credentialAccess }
        if l.contains("c2") || l.contains("beacon") || l.contains("tunnel") { return .c2 }
        if l.contains("exfil") || l.contains("staging") || l.contains("upload") { return .exfiltration }
        if l.contains("hidden") || l.contains("evas") || l.contains("stealth") { return .defenseEvasion }
        if l.contains("escalat") || l.contains("suid") || l.contains("root") { return .privilegeEscalation }
        if l.contains("ransom") || l.contains("wipe") { return .impact }
        if l.contains("screen") || l.contains("clipboard") || l.contains("camera") { return .collection }
        if l.contains("network") || l.contains("connection") { return .c2 }
        return .execution
    }

    // MARK: - MITRE → Stage Map

    private static let mitreMap: [String: KillChainStage] = [
        "T1595": .reconnaissance, "T1592": .reconnaissance, "T1589": .reconnaissance,
        "T1566": .initialAccess, "T1190": .initialAccess, "T1133": .initialAccess, "T1078": .initialAccess,
        "T1059": .execution, "T1204": .execution, "T1106": .execution, "T1053": .execution,
        "T1547": .persistence, "T1543": .persistence, "T1546": .persistence,
        "T1574": .persistence, "T1556": .persistence, "T1542": .persistence,
        "T1548": .privilegeEscalation, "T1134": .privilegeEscalation, "T1068": .privilegeEscalation,
        "T1562": .defenseEvasion, "T1070": .defenseEvasion, "T1036": .defenseEvasion,
        "T1027": .defenseEvasion, "T1014": .defenseEvasion, "T1112": .defenseEvasion,
        "T1055": .defenseEvasion,
        "T1555": .credentialAccess, "T1003": .credentialAccess, "T1110": .credentialAccess,
        "T1552": .credentialAccess, "T1539": .credentialAccess, "T1056": .credentialAccess,
        "T1082": .discovery, "T1057": .discovery, "T1083": .discovery, "T1046": .discovery,
        "T1021": .lateralMovement, "T1570": .lateralMovement,
        "T1005": .collection, "T1113": .collection, "T1115": .collection, "T1125": .collection,
        "T1071": .c2, "T1573": .c2, "T1102": .c2, "T1095": .c2, "T1572": .c2,
        "T1567": .exfiltration, "T1048": .exfiltration, "T1041": .exfiltration,
        "T1486": .impact, "T1485": .impact, "T1490": .impact,
    ]

    // MARK: - Scanner → Stage Map

    private static let scannerMap: [String: KillChainStage] = [
        "lolbin": .execution, "stealth": .defenseEvasion,
        "process_integrity": .defenseEvasion, "credential_access": .credentialAccess,
        "dyld_env": .execution, "masquerade": .defenseEvasion,
        "hidden_process": .defenseEvasion, "memory": .execution,
        "fake_prompt": .credentialAccess, "exploit_tool": .execution,
        "thread_anomaly": .execution, "clipboard": .collection,
        "network_anomaly": .c2, "cloud_c2": .c2,
        "xpc_auditor": .execution, "kext": .persistence,
        "auth_db": .privilegeEscalation, "persistence": .persistence,
        "persistence_monitor": .persistence, "event_tap": .collection,
        "tcc": .collection, "ransomware": .impact,
        "system_integrity": .defenseEvasion, "network_config": .discovery,
        "staging": .exfiltration, "xattr_abuse": .defenseEvasion,
        "hidden_file": .defenseEvasion, "usb_device": .collection,
        "log_integrity": .defenseEvasion, "screen_capture": .collection,
        "covert_channel": .c2, "firewall_routing": .defenseEvasion,
        "mach_port": .execution, "script_backdoor": .persistence,
        "download_provenance": .initialAccess, "crash_report": .discovery,
        "dns_tunnel": .c2, "timestomp": .defenseEvasion,
        "binary_integrity": .defenseEvasion, "dylib_hijack": .persistence,
        "certificate": .defenseEvasion, "browser_extension": .persistence,
        "entitlement": .privilegeEscalation, "security_evasion": .defenseEvasion,
        "vm_container": .discovery, "boot_security": .persistence,
        "kernel_integrity": .defenseEvasion, "dyld_cache": .defenseEvasion,
        "iokit_driver": .persistence, "application": .discovery,
        "browser_history": .collection, "supply_chain": .initialAccess,
        "phantom_dylib": .persistence,
        "inline_hook": .defenseEvasion,
    ]

    // MARK: - Helpers

    private static func group<T>(_ items: [T], by keyPath: KeyPath<T, String>) -> [String: [T]] {
        var m: [String: [T]] = [:]
        for item in items { m[item[keyPath: keyPath], default: []].append(item) }
        return m
    }

    private static func group<T>(_ items: [T], by key: (T) -> String) -> [String: [T]] {
        var m: [String: [T]] = [:]
        for item in items { m[key(item), default: []].append(item) }
        return m
    }

    private static func extractPeer(_ a: ProcessAnomaly) -> String? {
        for e in a.evidence {
            if e.contains(":") && e.first?.isNumber == true {
                return e.components(separatedBy: ":").first
            }
        }
        return nil
    }
}
