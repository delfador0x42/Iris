/// MITRE ATT&CK kill chain stages.
public enum KillChain: Int, Sendable, Codable, Comparable, CaseIterable {
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

/// Maps MITRE technique IDs to kill chain stages.
/// Key is the 5-char prefix (e.g., "T1059" not "T1059.001").
public let mitreToStage: [String: KillChain] = [
    // Reconnaissance
    "T1595": .reconnaissance, "T1592": .reconnaissance, "T1589": .reconnaissance,
    // Initial Access
    "T1566": .initialAccess, "T1190": .initialAccess, "T1133": .initialAccess,
    "T1078": .initialAccess,
    // Execution
    "T1059": .execution, "T1204": .execution, "T1106": .execution, "T1053": .execution,
    // Persistence
    "T1547": .persistence, "T1543": .persistence, "T1546": .persistence,
    "T1574": .persistence, "T1556": .persistence, "T1542": .persistence,
    // Privilege Escalation
    "T1548": .privilegeEscalation, "T1134": .privilegeEscalation,
    "T1068": .privilegeEscalation,
    // Defense Evasion
    "T1562": .defenseEvasion, "T1070": .defenseEvasion, "T1036": .defenseEvasion,
    "T1027": .defenseEvasion, "T1014": .defenseEvasion, "T1112": .defenseEvasion,
    "T1055": .defenseEvasion,
    // Credential Access
    "T1555": .credentialAccess, "T1003": .credentialAccess, "T1110": .credentialAccess,
    "T1552": .credentialAccess, "T1539": .credentialAccess, "T1056": .credentialAccess,
    // Discovery
    "T1082": .discovery, "T1057": .discovery, "T1083": .discovery, "T1046": .discovery,
    // Lateral Movement
    "T1021": .lateralMovement, "T1570": .lateralMovement,
    // Collection
    "T1005": .collection, "T1113": .collection, "T1115": .collection, "T1125": .collection,
    // Command & Control
    "T1071": .c2, "T1573": .c2, "T1102": .c2, "T1095": .c2, "T1572": .c2,
    // Exfiltration
    "T1567": .exfiltration, "T1048": .exfiltration, "T1041": .exfiltration,
    // Impact
    "T1486": .impact, "T1485": .impact, "T1490": .impact,
]

/// Classify a MITRE ID to kill chain stage. Falls back to keyword matching.
public func classifyMitre(_ mitre: String?, technique: String = "") -> KillChain {
    if let id = mitre, let stage = mitreToStage[String(id.prefix(5))] { return stage }
    return classifyByKeyword(technique)
}

private func classifyByKeyword(_ t: String) -> KillChain {
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
    return .execution
}
