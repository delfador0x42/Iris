import Foundation
import EndpointSecurity
import os.log

/// Endpoint Security client for real-time process monitoring.
/// Subscribes to EXEC/FORK/EXIT events and maintains a live process table.
/// XPC polls snapshot this table for the app.
class ESClient {

    let logger = Logger(subsystem: "com.wudan.iris.endpoint", category: "ESClient")

    /// The ES client handle
    private var client: OpaquePointer?

    /// Live process table: pid -> process info
    var processTable: [pid_t: ESProcessInfo] = [:]
    let processLock = NSLock()

    /// Ring buffer for event history — O(1) insert, bounded memory.
    /// Pre-allocated array with head index avoids O(n) removeFirst().
    private var eventRing: [ESProcessEvent?]
    private var eventRingHead = 0
    private var eventRingCount = 0
    private let eventHistoryLock = NSLock()
    let maxEventHistory = 5000

    /// Serial queue for processing ES events off the callback thread
    private let processingQueue = DispatchQueue(label: "com.wudan.iris.endpoint.processing")

    /// Event counters for periodic summary logging
    private var execCount: Int = 0
    private var forkCount: Int = 0
    private var exitCount: Int = 0
    private var lastSummaryTime = Date()

    /// XPC service for communication with main app
    private(set) var xpcService: ESXPCService?

    /// Whether the client is currently running
    private(set) var isRunning = false

    /// Error message if ES client failed to start
    var startupError: String?

    init() {
        eventRing = [ESProcessEvent?](repeating: nil, count: maxEventHistory)
        logger.info("ESClient initialized")
    }

    deinit {
        stop()
    }

    // MARK: - Lifecycle

    func start() throws {
        guard !isRunning else {
            logger.warning("[ES] ESClient already running, skipping start()")
            return
        }

        logger.info("[ES] Starting Endpoint Security client (PID \(getpid()), UID \(getuid()))...")

        logger.info("[ES] Creating XPC service...")
        xpcService = ESXPCService()
        xpcService?.esClient = self
        xpcService?.start()
        logger.info("[ES] XPC service started")

        logger.info("[ES] Calling es_new_client()...")
        var newClient: OpaquePointer?
        let result = es_new_client(&newClient) { [weak self] _, message in
            self?.handleMessage(message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let esClient = newClient else {
            let reason = esClientErrorDescription(result)
            logger.error("[ES] es_new_client FAILED: result=\(result.rawValue) reason=\(reason)")
            startupError = reason
            throw ESClientError.clientCreationFailed(reason)
        }

        self.client = esClient
        logger.info("[ES] es_new_client SUCCESS — client created")

        var selfToken = auditTokenForSelf()
        let muteResult = es_mute_process(esClient, &selfToken)
        logger.info("[ES] es_mute_process(self PID \(getpid())): \(muteResult == ES_RETURN_SUCCESS ? "OK" : "FAILED")")

        // Mute high-noise system paths to reduce event volume.
        // These are OS daemons that spawn/fork frequently but are never suspicious.
        muteNoisyPaths(esClient)

        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_SIGNAL,
            ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
        ]

        logger.info("[ES] Subscribing to \(events.count) event types (EXEC, FORK, EXIT, SIGNAL, CS_INVALIDATED)...")
        let subResult = es_subscribe(esClient, events, UInt32(events.count))
        guard subResult == ES_RETURN_SUCCESS else {
            logger.error("[ES] es_subscribe FAILED — deleting client")
            es_delete_client(esClient)
            self.client = nil
            throw ESClientError.subscriptionFailed
        }
        logger.info("[ES] es_subscribe SUCCESS — listening for events")

        seedProcessTable()

        isRunning = true
        startupError = nil
        logger.info("[ES] Endpoint Security client fully started — isRunning=true, processTable has \(self.processTable.count) entries")
    }

    func stop() {
        guard isRunning else { return }

        logger.info("Stopping Endpoint Security client...")

        if let client = client {
            es_unsubscribe_all(client)
            es_delete_client(client)
            self.client = nil
        }

        xpcService?.stop()
        xpcService = nil
        isRunning = false

        logger.info("Endpoint Security client stopped")
    }

    // MARK: - ES Event Handling

    private func handleMessage(_ message: UnsafePointer<es_message_t>) {
        es_retain_message(message)

        processingQueue.async { [weak self] in
            self?.processEvent(message)
            es_release_message(message)
        }
    }

    private func processEvent(_ message: UnsafePointer<es_message_t>) {
        switch message.pointee.event_type {

        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let target = message.pointee.event.exec.target.pointee
            let info = extractProcessInfo(from: target, event: message)
            let pid = audit_token_to_pid(target.audit_token)

            processLock.lock()
            processTable[pid] = info
            processLock.unlock()

            recordEvent(.exec, process: info)
            execCount += 1
            logger.debug("[ES] EXEC: \(info.name) (PID \(pid))")

        case ES_EVENT_TYPE_NOTIFY_FORK:
            let child = message.pointee.event.fork.child.pointee
            let childPid = audit_token_to_pid(child.audit_token)
            let parentPid = child.ppid
            let rpid = audit_token_to_pid(child.responsible_audit_token)
            let responsiblePid = (rpid > 0 && rpid != childPid) ? rpid : 0

            let stub = ESProcessInfo(
                pid: childPid, ppid: parentPid, responsiblePid: responsiblePid,
                path: esStringToSwift(child.executable.pointee.path),
                name: URL(fileURLWithPath: esStringToSwift(child.executable.pointee.path)).lastPathComponent,
                arguments: [],
                userId: audit_token_to_euid(child.audit_token),
                groupId: audit_token_to_egid(child.audit_token),
                codeSigningInfo: extractCodeSigningInfo(from: child),
                timestamp: Date()
            )

            processLock.lock()
            processTable[childPid] = stub
            processLock.unlock()

            recordEvent(.fork, process: stub)
            forkCount += 1
            logger.debug("[ES] FORK: child PID \(childPid) from parent PID \(parentPid)")

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            let proc = message.pointee.process.pointee
            let pid = audit_token_to_pid(proc.audit_token)

            processLock.lock()
            let exitingProcess = processTable.removeValue(forKey: pid)
            processLock.unlock()

            if let info = exitingProcess {
                recordEvent(.exit, process: info)
            }

            exitCount += 1
            logger.debug("[ES] EXIT: PID \(pid)")

        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            let target = message.pointee.event.signal.target.pointee
            let targetPid = audit_token_to_pid(target.audit_token)
            let sig = message.pointee.event.signal.sig
            // Only log interesting signals: SIGKILL(9), SIGTERM(15), SIGSTOP(17)
            if sig == 9 || sig == 15 || sig == 17 {
                let sourcePid = audit_token_to_pid(message.pointee.process.pointee.audit_token)
                logger.info("[ES] SIGNAL: PID \(sourcePid) sent signal \(sig) to PID \(targetPid)")
            }

        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            let proc = message.pointee.process.pointee
            let pid = audit_token_to_pid(proc.audit_token)
            let path = esStringToSwift(proc.executable.pointee.path)
            logger.warning("[ES] CS_INVALIDATED: PID \(pid) (\(path)) — code signature invalidated")

        default:
            break
        }

        // Log summary every 30 seconds
        let now = Date()
        if now.timeIntervalSince(lastSummaryTime) > 30 {
            processLock.lock()
            let tableSize = processTable.count
            processLock.unlock()
            logger.info("[ES] Event summary: exec=\(self.execCount) fork=\(self.forkCount) exit=\(self.exitCount) tableSize=\(tableSize)")
            self.lastSummaryTime = now
        }
    }

    // MARK: - Event History

    /// Record a process event into the ring buffer — O(1) insert, no allocations.
    func recordEvent(_ type: ESProcessEvent.EventType, process: ESProcessInfo) {
        let event = ESProcessEvent(eventType: type, process: process, timestamp: Date())
        eventHistoryLock.lock()
        let writeIndex = (eventRingHead + eventRingCount) % maxEventHistory
        eventRing[writeIndex] = event
        if eventRingCount < maxEventHistory {
            eventRingCount += 1
        } else {
            eventRingHead = (eventRingHead + 1) % maxEventHistory
        }
        eventHistoryLock.unlock()
    }

    /// Get the most recent N events from the ring buffer — O(n) read only.
    func getRecentEvents(limit: Int) -> [ESProcessEvent] {
        eventHistoryLock.lock()
        let count = min(limit, eventRingCount)
        var events: [ESProcessEvent] = []
        events.reserveCapacity(count)
        let start = (eventRingHead + eventRingCount - count) % maxEventHistory
        for i in 0..<count {
            let idx = (start + i) % maxEventHistory
            if let event = eventRing[idx] {
                events.append(event)
            }
        }
        eventHistoryLock.unlock()
        return events
    }

    // MARK: - Public API (for XPC)

    func getTrackedProcesses() -> [ESProcessInfo] {
        processLock.lock()
        let snapshot = Array(processTable.values)
        processLock.unlock()
        return snapshot
    }

    func getProcess(pid: pid_t) -> ESProcessInfo? {
        processLock.lock()
        let process = processTable[pid]
        processLock.unlock()
        return process
    }
}
