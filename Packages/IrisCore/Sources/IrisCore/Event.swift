import Foundation

// MARK: - The Universal Type

/// Every piece of data in Iris flows as an Event.
/// Kernel → engine → UI → CLI → Claude. One type. One path.
public struct Event: Identifiable, Sendable, Codable {
    public let id: UInt64
    public let ts: UInt64           // mach_absolute_time nanoseconds
    public let source: Source
    public let severity: Severity
    public let process: ProcessRef
    public let kind: Kind
    /// Raw ES fields — forensic context that Kind doesn't capture.
    /// cdhash, session_id, original_ppid, pgid, tty, mach_time, environment, etc.
    /// nil for non-ES events.
    public let fields: [String: String]?

    public init(
        id: UInt64, ts: UInt64 = Clock.now(),
        source: Source, severity: Severity,
        process: ProcessRef, kind: Kind,
        fields: [String: String]? = nil
    ) {
        self.id = id
        self.ts = ts
        self.source = source
        self.severity = severity
        self.process = process
        self.kind = kind
        self.fields = fields
    }
}

// MARK: - Source

public enum Source: String, Sendable, Codable {
    case endpoint   // ES extension
    case network    // Network filter
    case dns        // DNS proxy
    case proxy      // MITM proxy
    case probe      // Contradiction probes
    case scanner    // Batch scanners
    case engine     // ThreatEngine-generated alerts
}

// MARK: - Kind (tagged union of all event data)

public enum Kind: Sendable, Codable {
    // Process lifecycle
    case exec(parent: Int32, argv: [String])
    case fork(child: Int32)
    case exit(code: Int32)

    // File operations
    case fileWrite(path: String, entropy: Float)
    case fileOpen(path: String, flags: UInt32)
    case fileCreate(path: String)
    case fileRename(src: String, dst: String)
    case fileUnlink(path: String)

    // Network
    case connect(remote: NetAddr, proto: Proto)
    case listen(local: NetAddr, proto: Proto)
    case dns(query: String, qtype: UInt16, answers: [String])
    case httpFlow(method: String, host: String, path: String, status: UInt16, bytes: UInt64)

    // Security — AUTH decisions from ES
    case authExec(target: String, allowed: Bool)
    case authOpen(target: String, allowed: Bool)

    // Injection / privilege
    case injection(technique: String, targetPid: Int32)
    case privilege(op: String, uid: Int32)
    case signal(sig: Int32, targetPid: Int32)

    // Detection outputs
    case finding(scanner: String, technique: String, mitre: String, evidence: [String])
    case alert(rule: String, name: String, mitre: String, detail: String, chain: [UInt64])
    case probeResult(probe: String, verdict: Verdict, contradictions: [Contradiction])

    // System / security events from ES
    case procCheck(targetPid: Int32, flavor: Int32)
    case xpcConnect(service: String)
    case kextLoad(identifier: String)
    case mount(mountPoint: String)
    case tccModify(service: String, identity: String)
    case sshLogin(address: String, success: Bool)
    case csInvalidated
    case ptyGrant
    case btmLaunchItemAdd(path: String)
    case antiForensic(op: String, path: String)

    // System state
    case mute(path: String, events: [String])
    case extensionState(name: String, state: String)
}

// MARK: - Supporting Types

public struct ProcessRef: Sendable, Codable, Hashable {
    public let pid: Int32
    public let path: String
    public let sign: String     // signing ID, empty if unsigned
    public let ppid: Int32
    public let uid: UInt32
    public let cdhash: String   // hex, empty if unsigned
    public let teamId: String   // team ID, empty if none

    public init(
        pid: Int32, path: String, sign: String = "",
        ppid: Int32 = 0, uid: UInt32 = 0,
        cdhash: String = "", teamId: String = ""
    ) {
        self.pid = pid
        self.path = path
        self.sign = sign
        self.ppid = ppid
        self.uid = uid
        self.cdhash = cdhash
        self.teamId = teamId
    }

    public static let unknown = ProcessRef(pid: -1, path: "", sign: "")
}

public struct NetAddr: Sendable, Codable, Hashable {
    public let addr: String
    public let port: UInt16

    public init(_ addr: String, _ port: UInt16) {
        self.addr = addr
        self.port = port
    }
}

public enum Proto: String, Sendable, Codable {
    case tcp, udp, quic
}

public enum Verdict: String, Sendable, Codable {
    case clean, contradiction, error
}

public struct Contradiction: Sendable, Codable {
    public let label: String
    public let sourceA: String
    public let valueA: String
    public let sourceB: String
    public let valueB: String

    public init(label: String, sourceA: String, valueA: String, sourceB: String, valueB: String) {
        self.label = label
        self.sourceA = sourceA
        self.valueA = valueA
        self.sourceB = sourceB
        self.valueB = valueB
    }
}

public enum AuthAction: String, Sendable, Codable {
    case exec, open, mprotect
}

// MARK: - Clock

/// Monotonic nanosecond clock. One function, no Date overhead.
public enum Clock {
    private static var info: mach_timebase_info_data_t = {
        var i = mach_timebase_info_data_t()
        mach_timebase_info(&i)
        return i
    }()

    public static func now() -> UInt64 {
        let t = mach_absolute_time()
        return t * UInt64(info.numer) / UInt64(info.denom)
    }

    /// Convert nanosecond timestamp to Date (only for display, never in hot paths)
    public static func date(from ns: UInt64) -> Date {
        let current = now()
        let delta = TimeInterval(Int64(ns) - Int64(current)) / 1_000_000_000
        return Date().addingTimeInterval(delta)
    }
}

// MARK: - Event ID Generator

/// Monotonic ID generator. Uses os_unfair_lock for thread safety —
/// minimal overhead (no syscall in uncontended case), correct across actors.
public final class EventIDGen: @unchecked Sendable {
    private var counter: UInt64 = 0
    private var lock = os_unfair_lock()

    public static let shared = EventIDGen()

    private init() {}

    public func next() -> UInt64 {
        os_unfair_lock_lock(&lock)
        counter += 1
        let val = counter
        os_unfair_lock_unlock(&lock)
        return val
    }
}
