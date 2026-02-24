import Foundation
import os.log

/// Unix domain socket server at /tmp/iris.sock.
/// Receives JSON commands, streams JSONL responses.
/// This is the primary interface for Claude and iris-ctl.
///
/// Protocol:
///   Client sends one line of JSON: {"action":"tail","kind":"alert"}
///   Server responds with JSONL (one JSON object per line).
///   For streaming commands (tail), connection stays open.
///   For one-shot commands (status, scan), server sends response + closes.
///
/// Architecture:
///   Accept loop runs on a dedicated DispatchQueue (not the actor) because
///   accept() is blocking. Client handlers dispatch to async tasks for
///   actor-isolated work (calling other actors like EventStream, ThreatEngine).
actor IrisSocketServer {
    static let shared = IrisSocketServer()

    private let logger = Logger(subsystem: "com.wudan.iris", category: "Socket")
    private let socketPath = "/tmp/iris.sock"
    private var serverFD: Int32 = -1
    private var isRunning = false
    private let acceptQueue = DispatchQueue(label: "com.wudan.iris.socket.accept")

    func start() {
        guard !isRunning else { return }

        // Clean up stale socket
        unlink(socketPath)

        // Create AF_UNIX SOCK_STREAM
        serverFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverFD >= 0 else {
            logger.error("[SOCK] socket() failed: \(errno)")
            return
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let buf = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            socketPath.withCString { src in
                _ = strcpy(buf, src)
            }
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(serverFD, $0, addrLen) }
        }
        guard bindResult == 0 else {
            logger.error("[SOCK] bind() failed: \(errno)")
            close(serverFD)
            return
        }

        // Allow non-root clients
        chmod(socketPath, 0o666)

        guard listen(serverFD, 8) == 0 else {
            logger.error("[SOCK] listen() failed: \(errno)")
            close(serverFD)
            return
        }

        isRunning = true

        // Accept loop runs on a dedicated GCD queue — NOT the actor —
        // because accept() is blocking and would deadlock the actor.
        let fd = serverFD
        acceptQueue.async { [weak self] in
            self?.acceptLoop(serverFD: fd)
        }
        logger.info("[SOCK] Listening on \(self.socketPath)")
    }

    func stop() {
        isRunning = false
        if serverFD >= 0 {
            close(serverFD)
            serverFD = -1
        }
        unlink(socketPath)
        logger.info("[SOCK] Server stopped")
    }

    // MARK: - Accept Loop (runs on GCD queue, NOT actor)

    /// Blocking accept loop. Runs on acceptQueue.
    /// Each client gets a detached async Task for command handling.
    private nonisolated func acceptLoop(serverFD: Int32) {
        while true {
            var clientAddr = sockaddr_un()
            var clientLen = socklen_t(MemoryLayout<sockaddr_un>.size)
            let clientFD = withUnsafeMutablePointer(to: &clientAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(serverFD, $0, &clientLen)
                }
            }
            guard clientFD >= 0 else { break } // Server socket closed → exit loop

            // Each client handled in its own async task
            Task { [weak self] in
                await self?.handleClient(clientFD)
            }
        }
    }

    // MARK: - Client Handler

    private func handleClient(_ fd: Int32) async {
        defer { close(fd) }

        // Read command (one line) — nonisolated I/O
        guard let line = Self.readLine(fd: fd) else { return }
        guard let data = line.data(using: .utf8),
              let cmd = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let action = cmd["action"] as? String else {
            Self.writeLine(fd: fd, "{\"error\":\"invalid command\"}")
            return
        }

        switch action {
        case "tail":
            await handleTail(fd: fd, filter: cmd)
        case "status":
            await handleStatus(fd: fd)
        case "scan":
            await handleScan(fd: fd)
        case "probe":
            await handleProbe(fd: fd)
        case "alerts":
            await handleAlerts(fd: fd, limit: cmd["limit"] as? Int ?? 100)
        case "findings":
            await handleFindings(fd: fd, limit: cmd["limit"] as? Int ?? 500)
        case "stats":
            await handleStats(fd: fd)
        case "query":
            await handleQuery(fd: fd, params: cmd)
        case "snapshot":
            await handleSnapshot(fd: fd)
        case "dump":
            await handleDump(fd: fd)
        default:
            Self.writeLine(fd: fd, "{\"error\":\"unknown action: \(action)\"}")
        }
    }

    // MARK: - Streaming: tail

    private func handleTail(fd: Int32, filter: [String: Any]) async {
        let kindFilter = filter["kind"] as? String
        let sevFilter = filter["severity"] as? String

        // First send recent events as backfill
        let recent = await EventStream.shared.recent(50)
        for event in recent.reversed() {
            if let k = kindFilter, !event.kind.matches(k) { continue }
            if let s = sevFilter, let sev = Self.parseSeverity(s), event.severity < sev { continue }
            guard let json = Self.encodeEvent(event) else { continue }
            Self.writeLine(fd: fd, json)
        }

        // Subscribe to live events
        let (subId, stream) = await EventStream.shared.subscribe()
        defer { Task { await EventStream.shared.unsubscribe(subId) } }

        for await event in stream {
            if Task.isCancelled { break }
            if let k = kindFilter, !event.kind.matches(k) { continue }
            if let s = sevFilter, let sev = Self.parseSeverity(s), event.severity < sev { continue }
            guard let json = Self.encodeEvent(event) else { continue }
            if !Self.writeLine(fd: fd, json) { break } // Client disconnected
        }
    }

    // MARK: - One-shot Commands

    private func handleStatus(fd: Int32) async {
        let busStats = await SecurityEventBus.shared.stats()
        let streamStats = await EventStream.shared.stats()
        let threatStats = await ThreatEngine.shared.stats()

        let status: [String: Any] = [
            "eventBus": [
                "running": busStats.running,
                "ingested": busStats.ingested,
                "sequence": busStats.seq,
            ],
            "eventStream": [
                "total": streamStats.total,
                "alerts": streamStats.alerts,
                "findings": streamStats.findings,
                "ringCount": streamStats.ringCount,
                "suppressed": streamStats.suppressed,
                "jsonlPath": await EventStream.shared.jsonlPath,
            ],
            "threatEngine": [
                "eventsProcessed": threatStats.events,
                "alertsProduced": threatStats.alerts,
                "ruleBuckets": threatStats.ruleBuckets,
                "correlationRules": threatStats.correlations,
            ],
        ]
        Self.writeJSON(fd: fd, status)
    }

    private func handleScan(fd: Int32) async {
        // Stream progress as scanner completes
        let result = await SecurityAssessor.shared.scanThreats { progress in
            let p: [String: Any] = [
                "type": "progress",
                "completed": progress.completed,
                "total": progress.total,
                "scanner": progress.latestResult.name,
                "findings": progress.latestResult.anomalies.count,
            ]
            if let data = try? JSONSerialization.data(withJSONObject: p) {
                Self.writeLine(fd: fd, String(data: data, encoding: .utf8)!)
            }
        }

        // Send final result
        let summary: [String: Any] = [
            "type": "scanComplete",
            "totalFindings": result.totalFindings,
            "criticalCount": result.criticalCount,
            "highCount": result.highCount,
            "scannerCount": result.scannerCount,
            "durationMs": Int(result.scanDuration * 1000),
            "correlations": result.correlations.count,
            "campaigns": result.fusion.campaigns.count,
        ]
        Self.writeJSON(fd: fd, summary)
    }

    private func handleProbe(fd: Int32) async {
        let results = await ProbeRunner.shared.runAll()
        for result in results {
            let p: [String: Any] = [
                "probe": result.probeId,
                "name": result.probeName,
                "verdict": result.verdict.rawValue,
                "durationMs": result.durationMs,
                "contradictions": result.comparisons.filter { !$0.matches }.count,
            ]
            Self.writeJSON(fd: fd, p)
        }
    }

    private func handleAlerts(fd: Int32, limit: Int) async {
        let alerts = await EventStream.shared.alerts(limit)
        for event in alerts {
            guard let json = Self.encodeEvent(event) else { continue }
            Self.writeLine(fd: fd, json)
        }
    }

    private func handleFindings(fd: Int32, limit: Int) async {
        let findings = await EventStream.shared.findings(limit)
        for event in findings {
            guard let json = Self.encodeEvent(event) else { continue }
            Self.writeLine(fd: fd, json)
        }
    }

    private func handleStats(fd: Int32) async {
        let bus = await SecurityEventBus.shared.stats()
        let stream = await EventStream.shared.stats()
        let threat = await ThreatEngine.shared.stats()

        let stats: [String: Any] = [
            "threatEngine": [
                "eventsProcessed": threat.events,
                "alertsProduced": threat.alerts,
                "ruleBuckets": threat.ruleBuckets,
                "correlations": threat.correlations,
            ],
            "eventBus": [
                "running": bus.running,
                "ingested": bus.ingested,
            ],
            "eventStream": [
                "total": stream.total,
                "alerts": stream.alerts,
                "findings": stream.findings,
                "suppressed": stream.suppressed,
            ],
        ]
        Self.writeJSON(fd: fd, stats)
    }

    private func handleQuery(fd: Int32, params: [String: Any]) async {
        let events = await EventStream.shared.query(
            kind: params["kind"] as? String,
            severity: (params["severity"] as? String).flatMap { Self.parseSeverity($0) },
            since: params["since"] as? UInt64,
            limit: params["limit"] as? Int ?? 100)
        for event in events {
            guard let json = Self.encodeEvent(event) else { continue }
            Self.writeLine(fd: fd, json)
        }
    }

    private func handleSnapshot(fd: Int32) async {
        await handleStatus(fd: fd)
    }

    /// Full system dump — everything the GUI sees. This is Claude's window into Iris.
    private func handleDump(fd: Int32) async {
        // Gather data from all sources (MainActor stores + actors)
        let busStats = await SecurityEventBus.shared.stats()
        let streamStats = await EventStream.shared.stats()
        let threatStats = await ThreatEngine.shared.stats()
        let alertCounts = await AlertStore.shared.countBySeverity()
        let recentAlerts = await AlertStore.shared.recent(20)
        let probeResults = await ContradictionEngine.shared.results()

        // MainActor-isolated stores
        let guiState = await MainActor.run { () -> [String: Any] in
            let ps = ProcessStore.shared
            let net = SecurityStore.shared
            let dns = DNSStore.shared
            let proxy = ProxyStore.shared

            let topSuspicious: [[String: Any]] = ps.processes
                .filter(\.isSuspicious).prefix(10).map { p in
                    var entry: [String: Any] = [
                        "pid": p.pid, "name": p.name, "path": p.path,
                        "uid": p.userId,
                    ]
                    if !p.suspicionReasons.isEmpty {
                        entry["reasons"] = p.suspicionReasons.map(\.rawValue)
                    }
                    if p.arguments.count > 1 {
                        entry["args"] = Array(p.arguments.dropFirst())
                    }
                    return entry
                }

            let topConnections: [[String: Any]] = net.connections.prefix(20).map { c in
                [
                    "pid": c.processId,
                    "process": c.processName,
                    "remote": "\(c.remoteAddress):\(c.remotePort)",
                    "state": c.state.rawValue,
                    "bytesUp": c.bytesUp,
                    "bytesDown": c.bytesDown,
                    "country": c.remoteCountryCode ?? "",
                ]
            }

            let topDomains: [[String: Any]] = dns.topDomains.prefix(10).map { d in
                ["domain": d.domain, "count": d.count]
            }

            return [
                "processes": [
                    "total": ps.processes.count,
                    "suspicious": ps.suspiciousCount,
                    "esStatus": ps.esExtensionStatus.rawValue,
                    "topSuspicious": topSuspicious,
                ],
                "network": [
                    "connections": net.connections.count,
                    "bytesUp": net.totalBytesUp,
                    "bytesDown": net.totalBytesDown,
                    "countries": Array(net.uniqueCountries),
                    "topConnections": topConnections,
                ],
                "dns": [
                    "totalQueries": dns.totalQueries,
                    "isActive": dns.isActive,
                    "topDomains": topDomains,
                ],
                "proxy": [
                    "flowCount": proxy.totalFlowCount,
                    "isEnabled": proxy.isEnabled,
                    "interception": proxy.isInterceptionEnabled,
                ],
            ]
        }

        // Alerts summary
        let alertSummary: [String: Any] = [
            "critical": alertCounts[.critical] ?? 0,
            "high": alertCounts[.high] ?? 0,
            "medium": alertCounts[.medium] ?? 0,
            "low": alertCounts[.low] ?? 0,
            "recent": recentAlerts.map { a in
                [
                    "rule": a.ruleId, "name": a.name,
                    "severity": a.severity.label,
                    "process": a.processName,
                    "mitre": a.mitreId,
                    "time": ISO8601DateFormatter().string(from: a.timestamp),
                ] as [String: Any]
            },
        ]

        // Probes summary
        let probesSummary: [[String: Any]] = probeResults.map { r in
            [
                "probe": r.probeId, "name": r.probeName,
                "verdict": r.verdict.rawValue,
                "contradictions": r.comparisons.filter { !$0.matches }.count,
            ]
        }

        let dump: [String: Any] = [
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "eventBus": [
                "running": busStats.running,
                "ingested": busStats.ingested,
                "sequence": busStats.seq,
            ],
            "eventStream": [
                "total": streamStats.total,
                "alerts": streamStats.alerts,
                "findings": streamStats.findings,
                "suppressed": streamStats.suppressed,
                "ringCount": streamStats.ringCount,
            ],
            "threatEngine": [
                "eventsProcessed": threatStats.events,
                "alertsProduced": threatStats.alerts,
                "ruleBuckets": threatStats.ruleBuckets,
                "correlations": threatStats.correlations,
            ],
            "processes": guiState["processes"]!,
            "network": guiState["network"]!,
            "dns": guiState["dns"]!,
            "proxy": guiState["proxy"]!,
            "alerts": alertSummary,
            "probes": probesSummary,
        ]
        Self.writeJSON(fd: fd, dump)
    }

    // MARK: - Helpers (all static — no actor isolation needed for I/O)

    private static func parseSeverity(_ s: String) -> Severity? {
        switch s.lowercased() {
        case "info": return .info
        case "low": return .low
        case "medium": return .medium
        case "high": return .high
        case "critical": return .critical
        default: return nil
        }
    }

    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        return e
    }()

    private static func encodeEvent(_ event: Event) -> String? {
        guard let data = try? encoder.encode(event) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func readLine(fd: Int32) -> String? {
        var buf = [UInt8](repeating: 0, count: 1)
        var line = ""
        while true {
            let n = read(fd, &buf, 1)
            guard n > 0 else { return line.isEmpty ? nil : line }
            let ch = Character(UnicodeScalar(buf[0]))
            if ch == "\n" { return line }
            line.append(ch)
            if line.count > 4096 { return line }
        }
    }

    @discardableResult
    private static func writeLine(fd: Int32, _ text: String) -> Bool {
        let data = (text + "\n").utf8
        return data.withContiguousStorageIfAvailable { buf in
            write(fd, buf.baseAddress!, buf.count) == buf.count
        } ?? false
    }

    private static func writeJSON(fd: Int32, _ obj: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: obj),
              let str = String(data: data, encoding: .utf8) else { return }
        writeLine(fd: fd, str)
    }
}
