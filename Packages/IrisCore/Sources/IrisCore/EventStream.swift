import Foundation
import os.log

/// The single data path. Every Event flows through here.
/// Writes append-only JSONL to ~/.iris/events.jsonl.
/// Provides in-memory ring buffer for UI and streaming for CLI.
///
/// Data flow: Source → Event → EventStream → { UI, JSONL, CLI, macOS notification }
public actor EventStream {
    public static let shared = EventStream()

    private let logger = Logger(subsystem: "com.wudan.iris", category: "EventStream")
    private var ring: RingBuffer<Event>
    private var fileHandle: FileHandle?
    private let encoder: JSONEncoder
    private var subscribers: [UInt64: AsyncStream<Event>.Continuation] = [:]
    private var nextSubId: UInt64 = 0

    // Stats
    private var totalEmitted: UInt64 = 0
    private var totalSuppressed: UInt64 = 0
    private var alertCount: UInt64 = 0
    private var findingCount: UInt64 = 0

    // Dedup: suppress identical (kind+pid+key) events within a 2s window.
    // Key format: "kindDiscriminator|pid|pathOrTarget"
    // Alerts, findings, and probe results are NEVER suppressed.
    private var dedupLastSeen: [String: UInt64] = [:]  // key → last event timestamp
    private var dedupLastPrune: UInt64 = 0
    private let dedupWindowNs: UInt64 = 2_000_000_000  // 2 seconds

    public let jsonlPath: String

    private init() {
        self.ring = RingBuffer(capacity: 10000)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        self.encoder = encoder

        // Create ~/.iris/ directory and open events.jsonl
        let dir = NSHomeDirectory() + "/.iris"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        self.jsonlPath = dir + "/events.jsonl"

        // Rotate if > 10MB
        if let attrs = try? FileManager.default.attributesOfItem(atPath: jsonlPath),
           let size = attrs[.size] as? UInt64, size > 10_000_000 {
            let backup = dir + "/events.jsonl.1"
            try? FileManager.default.removeItem(atPath: backup)
            try? FileManager.default.moveItem(atPath: jsonlPath, toPath: backup)
        }

        FileManager.default.createFile(atPath: jsonlPath, contents: nil)
        self.fileHandle = FileHandle(forWritingAtPath: jsonlPath)
        fileHandle?.seekToEndOfFile()
    }

    // MARK: - Emit

    /// The ONE function to emit events. Everything goes through here.
    /// High-frequency identical events (same kind+pid+path within 2s) are
    /// suppressed to prevent JSONL bloat. Alerts/findings never suppressed.
    public func emit(_ event: Event) {
        // Rate-limit noisy events (file writes, opens, etc.)
        if let key = dedupKey(event) {
            if let lastTs = dedupLastSeen[key], event.ts - lastTs < dedupWindowNs {
                totalSuppressed += 1
                return
            }
            dedupLastSeen[key] = event.ts

            // Prune stale dedup entries every 10s
            if event.ts - dedupLastPrune > 10_000_000_000 {
                dedupLastPrune = event.ts
                let cutoff = event.ts - dedupWindowNs
                dedupLastSeen = dedupLastSeen.filter { $0.value > cutoff }
            }
        }

        totalEmitted += 1

        // Track stats
        switch event.kind {
        case .alert: alertCount += 1
        case .finding: findingCount += 1
        default: break
        }

        // Ring buffer (for UI)
        ring.append(event)

        // JSONL file (for Claude / CLI)
        if let data = try? encoder.encode(event) {
            fileHandle?.write(data)
            fileHandle?.write(Data([0x0A])) // newline
        }

        // Push to all subscribers (streaming CLI / tail)
        for (_, continuation) in subscribers {
            continuation.yield(event)
        }
    }

    /// Generate a dedup key for rate-limiting. Returns nil for events that
    /// should never be suppressed (alerts, findings, probes, lifecycle).
    private func dedupKey(_ event: Event) -> String? {
        let pid = event.process.pid
        switch event.kind {
        // Never suppress these
        case .alert, .finding, .probeResult, .exec, .fork, .exit,
             .extensionState, .mute:
            return nil
        // Rate-limit file events by path
        case .fileWrite(let path, _): return "fw|\(pid)|\(path)"
        case .fileOpen(let path, _):  return "fo|\(pid)|\(path)"
        case .fileCreate(let path):   return "fc|\(pid)|\(path)"
        case .fileRename(let src, _): return "fr|\(pid)|\(src)"
        case .fileUnlink(let path):   return "fu|\(pid)|\(path)"
        // Rate-limit network events by endpoint
        case .connect(let ep, _):     return "cn|\(pid)|\(ep.addr):\(ep.port)"
        case .listen(let ep, _):      return "ls|\(pid)|\(ep.addr):\(ep.port)"
        case .dns(let q, _, _):       return "dn|\(pid)|\(q)"
        case .httpFlow(_, let h, let p, _, _): return "hf|\(pid)|\(h)\(p)"
        // Rate-limit auth/injection/privilege/signal
        case .authExec(let t, _):     return "ae|\(pid)|\(t)"
        case .authOpen(let t, _):     return "ao|\(pid)|\(t)"
        case .injection(let t, let target): return "ij|\(pid)|\(t)|\(target)"
        case .privilege(let op, _):   return "pv|\(pid)|\(op)"
        case .signal(let sig, let target): return "sg|\(pid)|\(sig)|\(target)"
        // Rate-limit security events
        case .procCheck(let t, let f): return "pc|\(pid)|\(t)|\(f)"
        case .xpcConnect(let svc):    return "xc|\(pid)|\(svc)"
        case .antiForensic(let op, let p): return "af|\(pid)|\(op)|\(p)"
        case .ptyGrant:               return "pt|\(pid)"
        // Never suppress these — rare and always interesting
        case .kextLoad, .mount, .tccModify, .sshLogin,
             .csInvalidated, .btmLaunchItemAdd:
            return nil
        }
    }

    /// Emit a batch of events.
    public func emit(_ events: [Event]) {
        for event in events { emit(event) }
    }

    // MARK: - Query

    /// Recent events, newest first.
    public func recent(_ limit: Int = 100) -> [Event] {
        ring.newest(limit)
    }

    /// Events since a given sequence number.
    public func since(_ seq: UInt64) -> [Event] {
        // Events have monotonic IDs. Find the index in ring where id > seq.
        let all = ring.oldest()
        guard let firstIdx = all.firstIndex(where: { $0.id > seq }) else { return [] }
        return Array(all[firstIdx...])
    }

    /// Events matching a filter.
    public func query(
        kind: String? = nil,
        severity: Severity? = nil,
        since: UInt64? = nil,
        limit: Int = 100
    ) -> [Event] {
        var results: [Event] = []
        let all = ring.oldest()
        for event in all.reversed() {
            if let s = since, event.id <= s { break }
            if let k = kind, !event.kind.matches(k) { continue }
            if let sev = severity, event.severity < sev { continue }
            results.append(event)
            if results.count >= limit { break }
        }
        return results
    }

    /// All alerts in the ring, newest first.
    public func alerts(_ limit: Int = 200) -> [Event] {
        query(kind: "alert", limit: limit)
    }

    /// All findings in the ring, newest first.
    public func findings(_ limit: Int = 500) -> [Event] {
        query(kind: "finding", limit: limit)
    }

    // MARK: - Subscribe (streaming)

    /// Subscribe to live events. Returns an AsyncStream that yields events as they arrive.
    public func subscribe() -> (id: UInt64, stream: AsyncStream<Event>) {
        let id = nextSubId
        nextSubId += 1
        let stream = AsyncStream<Event> { continuation in
            self.subscribers[id] = continuation
            continuation.onTermination = { @Sendable _ in
                Task { await self.unsubscribe(id) }
            }
        }
        return (id, stream)
    }

    /// Unsubscribe from live events.
    public func unsubscribe(_ id: UInt64) {
        subscribers.removeValue(forKey: id)
    }

    // MARK: - Stats

    public func stats() -> (total: UInt64, alerts: UInt64, findings: UInt64, ringCount: Int, suppressed: UInt64) {
        (totalEmitted, alertCount, findingCount, ring.count, totalSuppressed)
    }

    // MARK: - Flush

    /// Force flush to disk. Call on app termination.
    public func flush() {
        // fileHandle.synchronizeFile() is deprecated but we use it for safety
        fileHandle?.synchronizeFile()
    }

    /// Clear the in-memory ring (does NOT clear the JSONL file).
    public func clearRing() {
        ring.clear()
    }
}

// MARK: - Event.Kind matching helper

extension Kind {
    /// Match against a kind name string (e.g., "alert", "finding", "exec").
    func matches(_ name: String) -> Bool {
        switch (self, name) {
        case (.exec, "exec"): true
        case (.fork, "fork"): true
        case (.exit, "exit"): true
        case (.fileWrite, "fileWrite"), (.fileWrite, "file"): true
        case (.fileOpen, "fileOpen"), (.fileOpen, "file"): true
        case (.fileRename, "fileRename"), (.fileRename, "file"): true
        case (.fileUnlink, "fileUnlink"), (.fileUnlink, "file"): true
        case (.connect, "connect"), (.connect, "network"): true
        case (.listen, "listen"), (.listen, "network"): true
        case (.dns, "dns"): true
        case (.httpFlow, "httpFlow"), (.httpFlow, "http"): true
        case (.authExec, "authExec"), (.authExec, "auth"): true
        case (.authOpen, "authOpen"), (.authOpen, "auth"): true
        case (.injection, "injection"): true
        case (.privilege, "privilege"): true
        case (.signal, "signal"): true
        case (.finding, "finding"): true
        case (.alert, "alert"): true
        case (.probeResult, "probeResult"), (.probeResult, "probe"): true
        case (.procCheck, "procCheck"): true
        case (.xpcConnect, "xpcConnect"): true
        case (.kextLoad, "kextLoad"): true
        case (.mount, "mount"): true
        case (.tccModify, "tccModify"): true
        case (.sshLogin, "sshLogin"): true
        case (.csInvalidated, "csInvalidated"): true
        case (.ptyGrant, "ptyGrant"): true
        case (.btmLaunchItemAdd, "btmLaunchItemAdd"): true
        case (.antiForensic, "antiForensic"): true
        // Group matches
        case (.procCheck, "security"), (.xpcConnect, "security"),
             (.kextLoad, "security"), (.tccModify, "security"),
             (.sshLogin, "security"), (.csInvalidated, "security"),
             (.antiForensic, "security"), (.btmLaunchItemAdd, "security"): true
        case (.mute, "mute"): true
        case (.extensionState, "extensionState"): true
        default: false
        }
    }
}
