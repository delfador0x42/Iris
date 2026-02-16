import Foundation
import os.log

/// Event bus that polls ES extension for security events via XPC
/// and feeds them to the DetectionEngine in real time.
/// Uses delta-fetch (sequence numbers) to avoid re-processing.
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
  private var isRunning = false
  private var pollTask: Task<Void, Never>?
  private var connection: NSXPCConnection?
  private var totalIngested: UInt64 = 0

  /// Start polling all event sources
  public func start() {
    guard !isRunning else { return }
    isRunning = true
    pollTask = Task { await pollLoop() }
    logger.info("[BUS] Event bus started")
  }

  /// Stop polling
  public func stop() {
    isRunning = false
    pollTask?.cancel()
    pollTask = nil
    connection?.invalidate()
    connection = nil
    logger.info("[BUS] Event bus stopped")
  }

  /// Current stats
  public func stats() -> (running: Bool, ingested: UInt64, seq: UInt64) {
    (isRunning, totalIngested, esSequence)
  }

  /// Feed events from an external source (e.g. ProcessStore)
  public func ingest(_ events: [SecurityEvent]) async {
    guard !events.isEmpty else { return }
    totalIngested += UInt64(events.count)
    await DetectionEngine.shared.processBatch(events)
  }

  /// Feed a single event
  public func ingest(_ event: SecurityEvent) async {
    totalIngested += 1
    await DetectionEngine.shared.process(event)
  }

  // MARK: - Polling

  private func pollLoop() async {
    while isRunning && !Task.isCancelled {
      await pollEndpointSecurity()
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
    let events: (UInt64, [Data]) = await withCheckedContinuation { cont in
      proxy.getSecurityEventsSince(sinceSeq, limit: 500) { maxSeq, data in
        cont.resume(returning: (maxSeq, data))
      }
    }

    let (maxSeq, dataArray) = events
    guard maxSeq > esSequence else { return }
    esSequence = maxSeq

    // Decode and convert
    var secEvents: [SecurityEvent] = []
    secEvents.reserveCapacity(dataArray.count)
    for data in dataArray {
      let raw: RawESEvent
      do {
        raw = try decoder.decode(RawESEvent.self, from: data)
      } catch {
        logger.error("[BUS] Decode failed: \(error.localizedDescription)")
        continue
      }
      secEvents.append(raw.toSecurityEvent())
    }

    if !secEvents.isEmpty {
      totalIngested += UInt64(secEvents.count)
      await DetectionEngine.shared.processBatch(secEvents)

      // Forward file events to PersistenceMonitor for real-time persistence detection
      for event in secEvents {
        guard let path = event.fields["target_path"] else { continue }
        let fileEvent: FileEventType? = switch event.eventType {
        case "file_write": .modified
        case "file_unlink": .deleted
        case "file_rename": .renamed
        default: nil
        }
        guard let fe = fileEvent else { continue }
        await PersistenceMonitor.shared.processFileEvent(
          path: path, eventType: fe, pid: event.pid, processPath: event.processPath)
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
