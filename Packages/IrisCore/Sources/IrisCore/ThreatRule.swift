import Foundation

// MARK: - Typed Rule Condition

/// A condition that evaluates against a typed Event.
/// No string dicts — pattern matches directly on Kind variants.
public struct ThreatCondition: Sendable {
    public let evaluate: @Sendable (Event) -> Bool

    public init(_ evaluate: @escaping @Sendable (Event) -> Bool) {
        self.evaluate = evaluate
    }
}

// MARK: - Single-Event Rule

/// A detection rule that matches one Event at a time.
/// Indexed by Kind discriminator for O(1) dispatch.
public struct ThreatRule: Identifiable, Sendable {
    public let id: String
    public let name: String
    /// Which Kind discriminators this rule matches (for index building)
    public let kinds: [String]
    public let conditions: [ThreatCondition]
    public let severity: Severity
    public let mitre: String
    public let mitreName: String

    public init(
        id: String, name: String, kinds: [String],
        conditions: [ThreatCondition],
        severity: Severity, mitre: String, mitreName: String
    ) {
        self.id = id
        self.name = name
        self.kinds = kinds
        self.conditions = conditions
        self.severity = severity
        self.mitre = mitre
        self.mitreName = mitreName
    }

    public func matches(_ event: Event) -> Bool {
        conditions.allSatisfy { $0.evaluate(event) }
    }

    public func detail(_ event: Event) -> String {
        switch event.kind {
        case .exec(_, let argv): "\(mitreName): \(argv.joined(separator: " "))"
        case .fileWrite(let path, _): "\(mitreName): \(path)"
        case .fileRename(_, let dst): "\(mitreName): \(dst)"
        case .injection(let tech, let target): "\(mitreName): \(tech) → pid \(target)"
        case .connect(let remote, _): "\(mitreName): \(remote.addr):\(remote.port)"
        case .dns(let query, _, _): "\(mitreName): \(query)"
        case .antiForensic(let op, let path): "\(mitreName): \(op) \(path)"
        case .tccModify(let svc, let id): "\(mitreName): \(svc) → \(id)"
        case .kextLoad(let id): "\(mitreName): \(id)"
        case .sshLogin(let addr, _): "\(mitreName): \(addr)"
        default: mitreName
        }
    }
}

// MARK: - Correlation Rule (streaming)

/// A multi-event streaming correlation rule.
/// Stages are evaluated in order against the Event stream.
public struct StreamCorrelationRule: Identifiable, Sendable {
    public let id: String
    public let name: String
    public let stages: [CorrelationStage]
    public let window: TimeInterval
    public let keyExtractor: @Sendable (Event) -> String
    public let severity: Severity
    public let mitre: String

    public init(
        id: String, name: String,
        stages: [CorrelationStage],
        window: TimeInterval,
        keyExtractor: @escaping @Sendable (Event) -> String,
        severity: Severity, mitre: String
    ) {
        self.id = id
        self.name = name
        self.stages = stages
        self.window = window
        self.keyExtractor = keyExtractor
        self.severity = severity
        self.mitre = mitre
    }
}

/// One stage of a streaming correlation.
public struct CorrelationStage: Sendable {
    public let kindName: String
    public let condition: ThreatCondition

    public init(_ kindName: String, _ condition: ThreatCondition = ThreatCondition { _ in true }) {
        self.kindName = kindName
        self.condition = condition
    }

    public func matches(_ event: Event) -> Bool {
        event.kind.discriminator == kindName && condition.evaluate(event)
    }
}

// MARK: - Kind discriminator

extension Kind {
    /// String discriminator for O(1) rule dispatch.
    public var discriminator: String {
        switch self {
        case .exec: "exec"
        case .fork: "fork"
        case .exit: "exit"
        case .fileWrite: "fileWrite"
        case .fileOpen: "fileOpen"
        case .fileCreate: "fileCreate"
        case .fileRename: "fileRename"
        case .fileUnlink: "fileUnlink"
        case .connect: "connect"
        case .listen: "listen"
        case .dns: "dns"
        case .httpFlow: "httpFlow"
        case .authExec: "authExec"
        case .authOpen: "authOpen"
        case .injection: "injection"
        case .privilege: "privilege"
        case .signal: "signal"
        case .finding: "finding"
        case .alert: "alert"
        case .probeResult: "probeResult"
        case .procCheck: "procCheck"
        case .xpcConnect: "xpcConnect"
        case .kextLoad: "kextLoad"
        case .mount: "mount"
        case .tccModify: "tccModify"
        case .sshLogin: "sshLogin"
        case .csInvalidated: "csInvalidated"
        case .ptyGrant: "ptyGrant"
        case .btmLaunchItemAdd: "btmLaunchItemAdd"
        case .antiForensic: "antiForensic"
        case .mute: "mute"
        case .extensionState: "extensionState"
        }
    }
}

// MARK: - Condition Helpers

extension ThreatCondition {
    /// Process is not Apple-signed.
    public static let notAppleSigned = ThreatCondition { event in
        !event.process.sign.hasPrefix("com.apple.")
    }

    /// Process path has given prefix.
    public static func pathPrefix(_ prefix: String) -> ThreatCondition {
        ThreatCondition { $0.process.path.hasPrefix(prefix) }
    }

    /// Process name (last path component) is in the given set.
    public static func nameIn(_ names: Set<String>) -> ThreatCondition {
        ThreatCondition { names.contains(($0.process.path as NSString).lastPathComponent) }
    }

    /// Process name is NOT in the given set.
    public static func nameNotIn(_ names: Set<String>) -> ThreatCondition {
        ThreatCondition { !names.contains(($0.process.path as NSString).lastPathComponent) }
    }
}
