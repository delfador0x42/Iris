import Foundation
import os.log

/// Event bus that polls ES extension for security events via XPC
/// and feeds them through the single unified data path:
///   Raw ES → Event → EventStream (THE ONE LOG)
///                   → ThreatEngine (rules) → AlertStore
///
/// EventStream is the single source of truth for all consumers (GUI, CLI, Claude).
public actor SecurityEventBus {
  public static let shared = SecurityEventBus()

  private let logger = Logger(subsystem: "com.wudan.iris", category: "EventBus")
  private let serviceName = "99HGW2AR62.com.wudan.iris.endpoint.xpc"
  private let decoder: JSONDecoder = {
    let d = JSONDecoder()
    d.dateDecodingStrategy = .iso8601
    return d
  }()

  private var esSequence: UInt64 = 0
  private var lastProcessTimestamp = Date.distantPast
  private var isRunning = false
  private var pollTask: Task<Void, Never>?
  private var alertBridgeTask: Task<Void, Never>?
  private var connection: NSXPCConnection?
  private var totalIngested: UInt64 = 0

  /// Start polling all event sources + alert bridge subscriber
  public func start() {
    guard !isRunning else { return }
    isRunning = true
    pollTask = Task { await pollLoop() }
    alertBridgeTask = Task { await bridgeThreatAlerts() }
    logger.info("[BUS] Event bus started")
  }

  /// Stop polling
  public func stop() {
    isRunning = false
    pollTask?.cancel()
    pollTask = nil
    alertBridgeTask?.cancel()
    alertBridgeTask = nil
    connection?.invalidate()
    connection = nil
    logger.info("[BUS] Event bus stopped")
  }

  /// Current stats
  public func stats() -> (running: Bool, ingested: UInt64, seq: UInt64) {
    (isRunning, totalIngested, esSequence)
  }

  /// Subscribe to EventStream for ThreatEngine alerts → forward to AlertStore
  /// for system notifications and HomeView display.
  private func bridgeThreatAlerts() async {
    let (subId, stream) = await EventStream.shared.subscribe()
    defer { Task { await EventStream.shared.unsubscribe(subId) } }

    for await event in stream {
      guard !Task.isCancelled else { break }
      guard event.source == .engine,
            case .alert(let rule, let name, let mitre, let detail, _) = event.kind
      else { continue }

      let severity: AnomalySeverity = switch event.severity {
      case .info, .low: .low
      case .medium: .medium
      case .high: .high
      case .critical: .critical
      }

      let alert = SecurityAlert(
        ruleId: rule, name: name, severity: severity,
        mitreId: mitre, mitreName: "",
        processName: (event.process.path as NSString).lastPathComponent,
        processPath: event.process.path,
        description: detail)
      await AlertStore.shared.add(alert)
    }
  }

  /// Feed events from an external source (e.g. DNSEventBridge, NetworkEventBridge)
  public func ingest(_ events: [Event]) async {
    guard !events.isEmpty else { return }
    totalIngested += UInt64(events.count)
    for event in events {
      await EventStream.shared.emit(event)
      await ThreatEngine.shared.process(event)
    }
  }

  /// Feed a single event
  public func ingest(_ event: Event) async {
    totalIngested += 1
    await EventStream.shared.emit(event)
    await ThreatEngine.shared.process(event)
  }

  // MARK: - Polling

  private func pollLoop() async {
    while isRunning && !Task.isCancelled {
      await pollEndpointSecurity()
      await pollProcessLifecycle()
      try? await Task.sleep(nanoseconds: 1_000_000_000)
    }
  }

  /// Poll ES extension for new security events via XPC
  private func pollEndpointSecurity() async {
    let conn = getConnection()
    guard let proxy = conn.remoteObjectProxyWithErrorHandler({ [weak self] error in
      Task { [weak self] in
        await self?.handleXPCError(error)
      }
    }) as? ESXPCBridge else { return }

    let sinceSeq = esSequence
    let result: (UInt64, [Data]) = await withCheckedContinuation { cont in
      proxy.getSecurityEventsSince(sinceSeq, limit: 500) { maxSeq, data in
        cont.resume(returning: (maxSeq, data))
      }
    }

    let (maxSeq, dataArray) = result
    guard maxSeq > esSequence else { return }
    esSequence = maxSeq

    // Decode directly to Event (no SecurityEvent intermediate)
    var events: [Event] = []
    events.reserveCapacity(dataArray.count)
    for data in dataArray {
      let raw: RawESEvent
      do {
        raw = try decoder.decode(RawESEvent.self, from: data)
      } catch {
        logger.error("[BUS] Decode failed: \(error.localizedDescription)")
        continue
      }
      events.append(raw.toEvent())
    }

    if !events.isEmpty {
      totalIngested += UInt64(events.count)

      // EventStream is the ONE data path
      for event in events {
        await EventStream.shared.emit(event)
        await ThreatEngine.shared.process(event)
      }

      // Forward file events to PersistenceMonitor for real-time persistence detection
      for event in events {
        let path: String
        let fe: FileEventType
        switch event.kind {
        case .fileWrite(let p, _): path = p; fe = .modified
        case .fileCreate(let p): path = p; fe = .created
        case .fileUnlink(let p): path = p; fe = .deleted
        case .fileRename(_, let dst): path = dst; fe = .renamed
        default: continue
        }
        await PersistenceMonitor.shared.processFileEvent(
          path: path, eventType: fe, pid: event.process.pid, processPath: event.process.path)
      }
    }
  }

  /// Poll ES extension for process lifecycle events (exec/fork/exit) via XPC.
  /// Uses timestamp-based dedup since eventRing has no sequence numbers.
  private func pollProcessLifecycle() async {
    let conn = getConnection()
    guard let proxy = conn.remoteObjectProxyWithErrorHandler({ [weak self] error in
      Task { [weak self] in await self?.handleXPCError(error) }
    }) as? ESXPCBridge else { return }

    let dataArray: [Data] = await withCheckedContinuation { cont in
      proxy.getRecentEvents(limit: 500) { data in
        cont.resume(returning: data)
      }
    }

    let cutoff = lastProcessTimestamp
    var maxTimestamp = cutoff
    var events: [Event] = []

    for data in dataArray {
      let raw: RawProcessEvent
      do {
        raw = try decoder.decode(RawProcessEvent.self, from: data)
      } catch {
        logger.error("[BUS] Process event decode failed: \(error.localizedDescription)")
        continue
      }
      guard raw.timestamp > cutoff else { continue }
      if raw.timestamp > maxTimestamp { maxTimestamp = raw.timestamp }
      events.append(raw.toEvent())
    }

    if !events.isEmpty {
      lastProcessTimestamp = maxTimestamp
      totalIngested += UInt64(events.count)

      // EventStream is the ONE data path
      for event in events {
        await EventStream.shared.emit(event)
        await ThreatEngine.shared.process(event)
      }
    }
  }

  private func getConnection() -> NSXPCConnection {
    if let c = connection { return c }
    let c = NSXPCConnection(machServiceName: serviceName)
    c.remoteObjectInterface = NSXPCInterface(with: ESXPCBridge.self)
    c.resume()
    connection = c
    return c
  }

  private func handleXPCError(_ error: Error) {
    logger.error("[BUS] XPC error: \(error.localizedDescription)")
    connection?.invalidate()
    connection = nil
  }
}
