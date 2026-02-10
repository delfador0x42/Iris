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

    /// Serial queue for processing ES events off the callback thread
    private let processingQueue = DispatchQueue(label: "com.wudan.iris.endpoint.processing")

    /// XPC service for communication with main app
    private(set) var xpcService: ESXPCService?

    /// Whether the client is currently running
    private(set) var isRunning = false

    /// Error message if ES client failed to start
    var startupError: String?

    init() {
        logger.info("ESClient initialized")
    }

    deinit {
        stop()
    }

    // MARK: - Lifecycle

    func start() throws {
        guard !isRunning else {
            logger.warning("ESClient already running")
            return
        }

        logger.info("Starting Endpoint Security client...")

        xpcService = ESXPCService()
        xpcService?.esClient = self
        xpcService?.start()

        var newClient: OpaquePointer?
        let result = es_new_client(&newClient) { [weak self] _, message in
            self?.handleMessage(message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let esClient = newClient else {
            let reason = esClientErrorDescription(result)
            logger.error("es_new_client failed: \(reason)")
            throw ESClientError.clientCreationFailed(reason)
        }

        self.client = esClient

        var selfToken = auditTokenForSelf()
        es_mute_process(esClient, &selfToken)
        logger.info("Muted own process (PID \(getpid()))")

        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT,
        ]

        let subResult = es_subscribe(esClient, events, UInt32(events.count))
        guard subResult == ES_RETURN_SUCCESS else {
            es_delete_client(esClient)
            self.client = nil
            throw ESClientError.subscriptionFailed
        }

        seedProcessTable()

        isRunning = true
        logger.info("Endpoint Security client started — monitoring EXEC/FORK/EXIT")
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
        guard let copy = es_copy_message(message) else {
            logger.error("es_copy_message failed")
            return
        }

        processingQueue.async { [weak self] in
            self?.processEvent(copy)
            es_free_message(copy)
        }
    }

    private func processEvent(_ message: UnsafeMutablePointer<es_message_t>) {
        switch message.pointee.event_type {

        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let target = message.pointee.event.exec.target.pointee
            let info = extractProcessInfo(from: target, event: message)
            let pid = audit_token_to_pid(target.audit_token)

            processLock.lock()
            processTable[pid] = info
            processLock.unlock()

            logger.debug("EXEC: \(info.name) (PID \(pid))")

        case ES_EVENT_TYPE_NOTIFY_FORK:
            let child = message.pointee.event.fork.child.pointee
            let childPid = audit_token_to_pid(child.audit_token)
            let parentPid = child.ppid

            let stub = ESProcessInfo(
                id: UUID(), pid: childPid, ppid: parentPid,
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

            logger.debug("FORK: child PID \(childPid) from parent PID \(parentPid)")

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            let proc = message.pointee.process.pointee
            let pid = audit_token_to_pid(proc.audit_token)

            processLock.lock()
            processTable.removeValue(forKey: pid)
            processLock.unlock()

            logger.debug("EXIT: PID \(pid)")

        default:
            break
        }
    }

    // MARK: - Process Table Seeding

    func seedProcessTable() {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0

        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else {
            logger.warning("Failed to get process list size for seeding")
            return
        }

        let count = size / MemoryLayout<kinfo_proc>.stride
        var procList = [kinfo_proc](repeating: kinfo_proc(), count: count)

        guard sysctl(&mib, 4, &procList, &size, nil, 0) == 0 else {
            logger.warning("Failed to get process list for seeding")
            return
        }

        let actualCount = size / MemoryLayout<kinfo_proc>.stride
        var seeded = 0

        processLock.lock()
        for i in 0..<actualCount {
            let proc = procList[i]
            let pid = proc.kp_proc.p_pid
            guard pid > 0 else { continue }

            let path = getProcessPath(pid)
            guard !path.isEmpty else { continue }

            let name = URL(fileURLWithPath: path).lastPathComponent
            let ppid = proc.kp_eproc.e_ppid
            let uid = proc.kp_eproc.e_ucred.cr_uid
            let gid = proc.kp_eproc.e_pcred.p_rgid
            let csInfo = getCodeSigningInfoForPath(path)

            processTable[pid] = ESProcessInfo(
                id: UUID(), pid: pid, ppid: ppid, path: path, name: name,
                arguments: [], userId: uid, groupId: gid,
                codeSigningInfo: csInfo, timestamp: Date()
            )
            seeded += 1
        }
        processLock.unlock()

        logger.info("Seeded process table with \(seeded) existing processes")
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
