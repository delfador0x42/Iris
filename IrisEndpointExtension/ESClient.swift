import EndpointSecurity
import Foundation
import os.log

/// Endpoint Security client for real-time process monitoring.
/// Subscribes to EXEC/FORK/EXIT events and maintains a live process table.
/// XPC polls snapshot this table for the app.
class ESClient {

  let logger = Logger(subsystem: "com.wudan.iris.endpoint", category: "ESClient")

  /// The ES client handle (internal for AUTH response from extension files)
  private(set) var client: OpaquePointer?

  /// Live process table: pid -> process info
  var processTable: [pid_t: ESProcessInfo] = [:]
  let processLock = NSLock()

  /// Ring buffer for process lifecycle events — O(1) insert, bounded memory.
  var eventRing: [ESProcessEvent?]
  var eventRingHead = 0
  var eventRingCount = 0
  let eventHistoryLock = NSLock()
  let maxEventHistory = 5000

  /// Separate ring buffer for security events (file, privilege, injection).
  /// Prevents high-volume file events from drowning out process lifecycle.
  var securityRing: [ESSecurityEvent?]
  var securityRingHead = 0
  var securityRingCount = 0
  let securityRingLock = NSLock()
  let maxSecurityHistory = 10000
  var securitySequence: UInt64 = 0

  /// Serial queue for processing ES events off the callback thread
  private let processingQueue = DispatchQueue(label: "com.wudan.iris.endpoint.processing")

  /// Event counters for periodic summary logging
  var execCount: Int = 0
  var forkCount: Int = 0
  var exitCount: Int = 0
  private var lastSummaryTime = Date()

  /// XPC service for communication with main app
  private(set) var xpcService: ESXPCService?

  /// Whether the client is currently running
  private(set) var isRunning = false

  /// Error message if ES client failed to start
  var startupError: String?

  /// Reusable buffer for proc_pidpath in recordSecurityEvent — avoids alloc/dealloc per event.
  /// Only accessed from processingQueue (serial), so no lock needed.
  let parentPathBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))

  init() {
    eventRing = [ESProcessEvent?](repeating: nil, count: maxEventHistory)
    securityRing = [ESSecurityEvent?](repeating: nil, count: maxSecurityHistory)
    logger.info("ESClient initialized")
  }

  deinit {
    stop()
    parentPathBuf.deallocate()
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

    // CRITICAL: Force-initialize ExecPolicy BEFORE creating the ES client.
    // AUTH events arrive on the BBReader thread immediately after es_new_client().
    // If the first AUTH handler triggers the lazy init of _auditMode, it reads
    // UserDefaults via synchronous XPC to cfprefsd. With es_subscribe() also doing
    // Mach IPC, the cfprefsd XPC deadlocks and the AUTH deadline expires — ES SIGKILLs
    // the extension, causing the crash loop seen in Console. Pre-init here ensures
    // the dispatch_once completes before any AUTH events can arrive.
    _ = ExecPolicy.auditMode
    logger.info("[ES] ExecPolicy pre-initialized (auditMode=\(ExecPolicy.auditMode))")

    logger.info("[ES] Calling es_new_client()...")
    var newClient: OpaquePointer?
    let result = es_new_client(&newClient) { [weak self] client, message in
      self?.handleMessage(client, message)
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
    logger.info(
      "[ES] es_mute_process(self PID \(getpid())): \(muteResult == ES_RETURN_SUCCESS ? "OK" : "FAILED")"
    )

    // Mute high-noise paths: event-specific rules first, then legacy blanket mutes.
    let muteSet = MuteSet.default
    let (eventMuted, globalMuted) = muteSet.apply(to: esClient)
    logger.info("[ES] MuteSet applied: \(eventMuted) event-specific, \(globalMuted) global rules")
    muteNoisyPaths(esClient)

    let events: [es_event_type_t] = [
      // Process lifecycle (original 5)
      ES_EVENT_TYPE_NOTIFY_EXEC,
      ES_EVENT_TYPE_NOTIFY_FORK,
      ES_EVENT_TYPE_NOTIFY_EXIT,
      ES_EVENT_TYPE_NOTIFY_SIGNAL,
      ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
      // File operations (credential theft, TCC manipulation, ransomware)
      ES_EVENT_TYPE_NOTIFY_OPEN,
      ES_EVENT_TYPE_NOTIFY_WRITE,
      ES_EVENT_TYPE_NOTIFY_UNLINK,
      ES_EVENT_TYPE_NOTIFY_RENAME,
      ES_EVENT_TYPE_NOTIFY_SETEXTATTR,
      // Privilege escalation
      ES_EVENT_TYPE_NOTIFY_SETUID,
      ES_EVENT_TYPE_NOTIFY_SETGID,
      ES_EVENT_TYPE_NOTIFY_SUDO,
      // Code injection
      ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
      ES_EVENT_TYPE_NOTIFY_GET_TASK,
      ES_EVENT_TYPE_NOTIFY_TRACE,
      // Memory/Execution (code injection, shellcode, JIT abuse)
      ES_EVENT_TYPE_NOTIFY_MMAP,
      ES_EVENT_TYPE_NOTIFY_MPROTECT,
      ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME,
      // System changes
      ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
      ES_EVENT_TYPE_NOTIFY_MOUNT,
      ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
      ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
      ES_EVENT_TYPE_NOTIFY_TCC_MODIFY,
      // Authentication
      ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
      ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
      // Nation-state detection: hardware access, file duplication, ownership
      ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,
      ES_EVENT_TYPE_NOTIFY_COPYFILE,
      // Nation-state detection: Unix domain sockets (covert channels, C2)
      ES_EVENT_TYPE_NOTIFY_UIPC_BIND,
      ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
      // Nation-state detection: authentication and session tracking
      ES_EVENT_TYPE_NOTIFY_AUTHENTICATION,
      ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN,
      ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT,
      // Authorization (real-time blocking)
      ES_EVENT_TYPE_AUTH_EXEC,
      ES_EVENT_TYPE_AUTH_MPROTECT,
      ES_EVENT_TYPE_AUTH_OPEN,
    ]

    logger.info("[ES] Subscribing to \(events.count) event types...")
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
    logger.info(
      "[ES] Endpoint Security client fully started — isRunning=true, processTable has \(self.processTable.count) entries"
    )
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

  private func handleMessage(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>) {
    // AUTH events must be processed synchronously in the callback to guarantee
    // the es_client_t handle is valid when es_respond_auth_result() is called.
    // We pass the callback's client handle directly — it's guaranteed valid here,
    // unlike self.client which could be nil if stop() races with the callback.
    if message.pointee.action_type == ES_ACTION_TYPE_AUTH {
      processAuthEvent(client, message)
      return
    }

    es_retain_message(message)
    processingQueue.async { [weak self] in
      self?.processNotifyEvent(message)
      es_release_message(message)
    }
  }

  private func processAuthEvent(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>) {
    switch message.pointee.event_type {
    case ES_EVENT_TYPE_AUTH_EXEC: handleAuthExec(client, message)
    case ES_EVENT_TYPE_AUTH_MPROTECT: handleAuthMprotect(client, message)
    case ES_EVENT_TYPE_AUTH_OPEN: handleAuthOpen(client, message)
    default:
      // Unknown AUTH event — must still respond to avoid kernel killing the process
      logger.error("[ES] Unknown AUTH event type \(message.pointee.event_type.rawValue) — allowing")
      es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
    }
  }

  private func processNotifyEvent(_ message: UnsafePointer<es_message_t>) {
    switch message.pointee.event_type {

    // Process lifecycle (handlers in ESClient+ProcessLifecycle.swift)
    case ES_EVENT_TYPE_NOTIFY_EXEC: handleExec(message)
    case ES_EVENT_TYPE_NOTIFY_FORK: handleFork(message)
    case ES_EVENT_TYPE_NOTIFY_EXIT: handleExit(message)
    case ES_EVENT_TYPE_NOTIFY_SIGNAL: handleSignal(message)
    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED: handleCSInvalidated(message)

    // File operations → security event ring buffer
    case ES_EVENT_TYPE_NOTIFY_OPEN: handleFileOpen(message)
    case ES_EVENT_TYPE_NOTIFY_WRITE: handleFileWrite(message)
    case ES_EVENT_TYPE_NOTIFY_UNLINK: handleFileUnlink(message)
    case ES_EVENT_TYPE_NOTIFY_RENAME: handleFileRename(message)
    case ES_EVENT_TYPE_NOTIFY_SETEXTATTR: handleSetExtattr(message)

    // Privilege escalation
    case ES_EVENT_TYPE_NOTIFY_SETUID: handleSetuid(message)
    case ES_EVENT_TYPE_NOTIFY_SETGID: handleSetgid(message)
    case ES_EVENT_TYPE_NOTIFY_SUDO: handleSudo(message)

    // Code injection
    case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE: handleRemoteThreadCreate(message)
    case ES_EVENT_TYPE_NOTIFY_GET_TASK: handleGetTask(message)
    case ES_EVENT_TYPE_NOTIFY_TRACE: handleTrace(message)

    // Memory/Execution
    case ES_EVENT_TYPE_NOTIFY_MMAP: handleMmap(message)
    case ES_EVENT_TYPE_NOTIFY_MPROTECT: handleMprotect(message)
    case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME: handleProcSuspendResume(message)

    // System changes
    case ES_EVENT_TYPE_NOTIFY_KEXTLOAD: handleKextLoad(message)
    case ES_EVENT_TYPE_NOTIFY_MOUNT: handleMount(message)
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD: handleBTMLaunchItemAdd(message)
    case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT: handleXPCConnect(message)
    case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY: handleTCCModify(message)

    // Authentication
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN: handleSSHLogin(message)
    case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED: handleXProtectMalware(message)

    // Nation-state detection events
    case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN: handleIOKitOpen(message)
    case ES_EVENT_TYPE_NOTIFY_COPYFILE: handleCopyfile(message)
    case ES_EVENT_TYPE_NOTIFY_UIPC_BIND: handleUIPCBind(message)
    case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: handleUIPCConnect(message)
    case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION: handleAuthentication(message)
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN: handleSessionLogin(message)
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT: handleSessionLogout(message)

    default:
      break
    }

    // Log summary every 30 seconds (safe: only runs on processingQueue, no data race with counters)
    let now = Date()
    if now.timeIntervalSince(lastSummaryTime) > 30 {
      processLock.lock()
      let tableSize = processTable.count
      processLock.unlock()
      logger.info(
        "[ES] Event summary: exec=\(self.execCount) fork=\(self.forkCount) exit=\(self.exitCount) tableSize=\(tableSize)"
      )
      self.lastSummaryTime = now
    }
  }

  // MARK: - Public API (for XPC)

  /// Process count without materializing the full array — O(1).
  var processCount: Int {
    processLock.lock()
    defer { processLock.unlock() }
    return processTable.count
  }

  func getTrackedProcesses() -> [ESProcessInfo] {
    processLock.lock()
    defer { processLock.unlock() }
    return Array(processTable.values)
  }

}
