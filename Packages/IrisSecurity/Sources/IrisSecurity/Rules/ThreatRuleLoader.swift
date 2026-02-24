import Foundation

/// Converts existing DetectionRules → ThreatRules and loads into ThreatEngine.
/// Transitional — once old rule types are retired, this converts directly.
public enum ThreatRuleLoader {

    /// Map old eventType strings to Kind discriminators.
    /// Must stay in sync with EventBridge.mapESEventType().
    private static let eventTypeToKind: [String: String] = [
        // Process lifecycle
        "exec": "exec",
        "fork": "fork",
        "exit": "exit",
        // File operations
        "file_write": "fileWrite",
        "file_open": "fileOpen",
        "file_create": "fileCreate",
        "file_rename": "fileRename",
        "file_unlink": "fileUnlink",
        "file_setextattr": "fileWrite",    // EventBridge maps to fileWrite
        "file_link": "fileCreate",          // EventBridge maps to fileCreate
        // Network
        "connection": "connect",
        "dns_query": "dns",
        "ssh_login": "sshLogin",
        // Auth decisions
        "auth_exec": "authExec",
        "auth_open": "authOpen",
        // Injection
        "task_for_pid": "injection",
        "get_task": "injection",
        "get_task_read": "injection",
        "get_task_inspect": "injection",
        "remote_thread_create": "injection",
        "ptrace": "injection",
        // Privilege escalation
        "signal": "signal",
        "mprotect": "privilege",
        "setuid": "privilege",
        "setgid": "privilege",
        "sudo": "privilege",
        "set_owner": "privilege",
        "proc_suspend_resume": "privilege",
        "authentication": "privilege",
        // System / security events
        "kext_load": "kextLoad",
        "mount": "mount",
        "btm_launch_item_add": "btmLaunchItemAdd",
        "tcc_modify": "tccModify",
        "cs_invalidated": "csInvalidated",
        "proc_check": "procCheck",
        "xpc_connect": "xpcConnect",
        "pty_grant": "ptyGrant",
        // Anti-forensics
        "delete_extattr": "antiForensic",
        "file_truncate": "antiForensic",
        "file_utimes": "antiForensic",
        "file_setmode": "antiForensic",
        "file_setflags": "antiForensic",
        // Nation-state / advanced
        "iokit_open": "antiForensic",
        "copyfile": "antiForensic",
        "uipc_bind": "antiForensic",
        "uipc_connect": "antiForensic",
    ]

    /// Convert all existing rules and load into ThreatEngine
    public static func loadAll() async {
        let oldSimple = RuleLoader.allSimpleRules()
        let threatRules = oldSimple.compactMap { convert($0) }

        // Convert correlation rules to StreamCorrelationRules
        let oldCorrelation = RuleLoader.allCorrelationRules()
        let streamRules = oldCorrelation.compactMap { convertCorrelation($0) }

        await ThreatEngine.shared.loadRules(simple: threatRules, correlation: streamRules)
    }

    private static func convert(_ old: DetectionRule) -> ThreatRule? {
        guard let kindName = eventTypeToKind[old.eventType] else { return nil }

        let severity: Severity = switch old.severity {
        case .low: .low
        case .medium: .medium
        case .high: .high
        case .critical: .critical
        }

        // Convert old conditions to typed ThreatConditions
        let conditions = old.conditions.map { convertCondition($0) }

        return ThreatRule(
            id: old.id, name: old.name,
            kinds: [kindName],
            conditions: conditions,
            severity: severity,
            mitre: old.mitreId,
            mitreName: old.mitreName)
    }

    private static func convertCondition(_ old: RuleCondition) -> ThreatCondition {
        switch old {
        case .processNotAppleSigned:
            return .notAppleSigned
        case .processNameIn(let names):
            return .nameIn(Set(names))
        case .processNameNotIn(let names):
            return .nameNotIn(Set(names))
        case .processPathHasPrefix(let prefix):
            return .pathPrefix(prefix)
        case .fieldEquals(let key, let value):
            return ThreatCondition { event in fieldValue(event, key: key) == value }
        case .fieldContains(let key, let substring):
            return ThreatCondition { event in fieldValue(event, key: key)?.contains(substring) == true }
        case .fieldMatchesRegex(let key, let pattern):
            let regex = try? NSRegularExpression(pattern: pattern)
            return ThreatCondition { event in
                guard let val = fieldValue(event, key: key), let r = regex else { return false }
                return r.firstMatch(in: val, range: NSRange(val.startIndex..., in: val)) != nil
            }
        case .fieldHasPrefix(let key, let prefix):
            return ThreatCondition { event in fieldValue(event, key: key)?.hasPrefix(prefix) == true }
        case .parentNameIn(let names):
            let nameSet = Set(names)
            return ThreatCondition { event in
                if case .exec(let parent, _) = event.kind {
                    // We don't have parent name in Event, only parent PID
                    // Accept all — this condition will be tightened when we add parent tracking
                    return parent != 0
                }
                return false
            }
        }
    }

    /// Extract field values from the new typed Event.
    /// Maps old string-key fields to Kind data, then falls through to raw ES fields.
    private static func fieldValue(_ event: Event, key: String) -> String? {
        // Try typed extraction from Kind variants first
        switch key {
        case "target_path":
            switch event.kind {
            case .fileWrite(let p, _): return p
            case .fileOpen(let p, _): return p
            case .fileCreate(let p): return p
            case .fileRename(_, let dst): return dst
            case .fileUnlink(let p): return p
            case .btmLaunchItemAdd(let p): return p
            case .antiForensic(_, let p): return p
            case .mount(let p): return p
            case .authExec(let t, _): return t
            case .authOpen(let t, _): return t
            default: break
            }
        case "source_path":
            if case .fileRename(let src, _) = event.kind { return src }
        case "argv":
            if case .exec(_, let argv) = event.kind { return argv.joined(separator: " ") }
        case "parent_pid":
            if case .exec(let parent, _) = event.kind { return "\(parent)" }
        case "child_pid":
            if case .fork(let child) = event.kind { return "\(child)" }
        case "target_pid":
            switch event.kind {
            case .injection(_, let target): return "\(target)"
            case .signal(_, let target): return "\(target)"
            case .procCheck(let target, _): return "\(target)"
            default: break
            }
        case "signal":
            if case .signal(let sig, _) = event.kind { return "\(sig)" }
        case "remote_host", "remote_address":
            switch event.kind {
            case .connect(let remote, _): return remote.addr
            case .sshLogin(let addr, _): return addr
            default: break
            }
        default:
            break
        }
        // Fallthrough: raw ES fields preserved on Event (cdhash, detail, etc.)
        return event.fields?[key]
    }

    private static func convertCorrelation(_ old: CorrelationRule) -> StreamCorrelationRule? {
        let stages = old.stages.compactMap { stage -> CorrelationStage? in
            guard let kindName = eventTypeToKind[stage.eventType] else { return nil }
            let conditions = stage.conditions.map { convertCondition($0) }
            return CorrelationStage(kindName, ThreatCondition { event in
                conditions.allSatisfy { $0.evaluate(event) }
            })
        }
        guard stages.count == old.stages.count else { return nil }

        let severity: Severity = switch old.severity {
        case .low: .low
        case .medium: .medium
        case .high: .high
        case .critical: .critical
        }

        let keyExtractor: @Sendable (Event) -> String = switch old.correlationKey {
        case .pid: { "\($0.process.pid)" }
        case .processPath: { $0.process.path }
        case .signingId: { $0.process.sign.isEmpty ? $0.process.path : $0.process.sign }
        }

        return StreamCorrelationRule(
            id: old.id, name: old.name,
            stages: stages,
            window: old.timeWindow,
            keyExtractor: keyExtractor,
            severity: severity,
            mitre: old.mitreId)
    }
}
