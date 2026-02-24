import EndpointSecurity
import Foundation
import os.log

class ESClient {

  let logger = Logger(subsystem: "com.wudan.iris.endpoint", category: "ESClient")

  private(set) var client: OpaquePointer?

  var processTable: [pid_t: ESProcessInfo] = [:]
  let processLock = NSLock()

  var eventRing: [ESProcessEvent?]
  var eventRingHead = 0
  var eventRingCount = 0
  let eventHistoryLock = NSLock()
  let maxEventHistory = 5000

  var securityRing: [ESSecurityEvent?]
  var securityRingHead = 0
  var securityRingCount = 0
  let securityRingLock = NSLock()
  let maxSecurityHistory = 10000
  var securitySequence: UInt64 = 0

  private let processingQueue = DispatchQueue(label: "com.wudan.iris.endpoint.processing")

  var execCount: Int = 0
  var forkCount: Int = 0
  var exitCount: Int = 0
  private var lastSummaryTime = Date()

  private(set) var xpcService: ESXPCService?
  private(set) var isRunning = false
  var startupError: String?

  /// Reusable buffer for proc_pidpath — only accessed from processingQueue (serial)
  let parentPathBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))

  init() {
    eventRing = [ESProcessEvent?](repeating: nil, count: maxEventHistory)
    securityRing = [ESSecurityEvent?](repeating: nil, count: maxSecurityHistory)
  }

  deinit {
    stop()
    parentPathBuf.deallocate()
  }

  // MARK: - Lifecycle

  func start() throws {
    guard !isRunning else { return }

    xpcService = ESXPCService()
    xpcService?.esClient = self
    xpcService?.start()

    // Pre-init ExecPolicy before any AUTH events can arrive (cfprefsd deadlock prevention)
    _ = ExecPolicy.auditMode

    var newClient: OpaquePointer?
    let result = es_new_client(&newClient) { [weak self] client, message in
      self?.handleMessage(client, message)
    }

    guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let esClient = newClient else {
      let reason = esClientErrorDescription(result)
      startupError = reason
      throw ESClientError.clientCreationFailed(reason)
    }

    self.client = esClient

    var selfToken = auditTokenForSelf()
    es_mute_process(esClient, &selfToken)

    let muteSet = MuteSet.default
    muteSet.apply(to: esClient)
    muteNoisyPaths(esClient)

    let events: [es_event_type_t] = [
      // Process lifecycle
      ES_EVENT_TYPE_NOTIFY_EXEC,
      ES_EVENT_TYPE_NOTIFY_FORK,
      ES_EVENT_TYPE_NOTIFY_EXIT,
      ES_EVENT_TYPE_NOTIFY_SIGNAL,
      ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
      // File operations
      ES_EVENT_TYPE_NOTIFY_OPEN,
      ES_EVENT_TYPE_NOTIFY_WRITE,
      ES_EVENT_TYPE_NOTIFY_UNLINK,
      ES_EVENT_TYPE_NOTIFY_RENAME,
      ES_EVENT_TYPE_NOTIFY_SETEXTATTR,
      ES_EVENT_TYPE_NOTIFY_CREATE,
      ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR,
      ES_EVENT_TYPE_NOTIFY_LINK,
      ES_EVENT_TYPE_NOTIFY_SETOWNER,
      // Anti-forensics
      ES_EVENT_TYPE_NOTIFY_TRUNCATE,
      ES_EVENT_TYPE_NOTIFY_UTIMES,
      ES_EVENT_TYPE_NOTIFY_SETMODE,
      ES_EVENT_TYPE_NOTIFY_SETFLAGS,
      // Privilege escalation
      ES_EVENT_TYPE_NOTIFY_SETUID,
      ES_EVENT_TYPE_NOTIFY_SETGID,
      ES_EVENT_TYPE_NOTIFY_SUDO,
      // Code injection
      ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
      ES_EVENT_TYPE_NOTIFY_GET_TASK,
      ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
      ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT,
      ES_EVENT_TYPE_NOTIFY_TRACE,
      // Memory/Execution
      ES_EVENT_TYPE_NOTIFY_MMAP,
      ES_EVENT_TYPE_NOTIFY_MPROTECT,
      ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME,
      // Process introspection
      ES_EVENT_TYPE_NOTIFY_PROC_CHECK,
      ES_EVENT_TYPE_NOTIFY_PTY_GRANT,
      ES_EVENT_TYPE_NOTIFY_PTY_CLOSE,
      // System changes
      ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
      ES_EVENT_TYPE_NOTIFY_MOUNT,
      ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
      ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
      ES_EVENT_TYPE_NOTIFY_TCC_MODIFY,
      // Authentication
      ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
      ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
      // Nation-state detection
      ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,
      ES_EVENT_TYPE_NOTIFY_COPYFILE,
      ES_EVENT_TYPE_NOTIFY_UIPC_BIND,
      ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
      ES_EVENT_TYPE_NOTIFY_AUTHENTICATION,
      ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN,
      ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT,
      // Authorization (real-time blocking)
      ES_EVENT_TYPE_AUTH_EXEC,
      ES_EVENT_TYPE_AUTH_MPROTECT,
      ES_EVENT_TYPE_AUTH_OPEN,
    ]

    let subResult = es_subscribe(esClient, events, UInt32(events.count))
    guard subResult == ES_RETURN_SUCCESS else {
      es_delete_client(esClient)
      self.client = nil
      throw ESClientError.subscriptionFailed
    }

    seedProcessTable()
    isRunning = true
    startupError = nil
    logger.info("[ES] Started — \(events.count) event types, \(self.processTable.count) seeded processes")
  }

  func stop() {
    guard isRunning else { return }
    if let client = client {
      es_unsubscribe_all(client)
      es_delete_client(client)
      self.client = nil
    }
    xpcService?.stop()
    xpcService = nil
    isRunning = false
  }

  // MARK: - Event Dispatch

  private func handleMessage(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>) {
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
      es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
    }
  }

  private func processNotifyEvent(_ message: UnsafePointer<es_message_t>) {
    switch message.pointee.event_type {
    // Process lifecycle
    case ES_EVENT_TYPE_NOTIFY_EXEC: handleExec(message)
    case ES_EVENT_TYPE_NOTIFY_FORK: handleFork(message)
    case ES_EVENT_TYPE_NOTIFY_EXIT: handleExit(message)
    case ES_EVENT_TYPE_NOTIFY_SIGNAL: handleSignal(message)
    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED: handleCSInvalidated(message)
    // File operations
    case ES_EVENT_TYPE_NOTIFY_OPEN: handleFileOpen(message)
    case ES_EVENT_TYPE_NOTIFY_WRITE: handleFileWrite(message)
    case ES_EVENT_TYPE_NOTIFY_UNLINK: handleFileUnlink(message)
    case ES_EVENT_TYPE_NOTIFY_RENAME: handleFileRename(message)
    case ES_EVENT_TYPE_NOTIFY_SETEXTATTR: handleSetExtattr(message)
    case ES_EVENT_TYPE_NOTIFY_CREATE: handleFileCreate(message)
    case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR: handleDeleteExtattr(message)
    case ES_EVENT_TYPE_NOTIFY_LINK: handleLink(message)
    case ES_EVENT_TYPE_NOTIFY_SETOWNER: handleSetOwner(message)
    // Anti-forensics
    case ES_EVENT_TYPE_NOTIFY_TRUNCATE: handleTruncate(message)
    case ES_EVENT_TYPE_NOTIFY_UTIMES: handleUtimes(message)
    case ES_EVENT_TYPE_NOTIFY_SETMODE: handleSetMode(message)
    case ES_EVENT_TYPE_NOTIFY_SETFLAGS: handleSetFlags(message)
    // Privilege escalation
    case ES_EVENT_TYPE_NOTIFY_SETUID: handleSetuid(message)
    case ES_EVENT_TYPE_NOTIFY_SETGID: handleSetgid(message)
    case ES_EVENT_TYPE_NOTIFY_SUDO: handleSudo(message)
    // Code injection
    case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE: handleRemoteThreadCreate(message)
    case ES_EVENT_TYPE_NOTIFY_GET_TASK: handleGetTask(message)
    case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ: handleGetTaskRead(message)
    case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT: handleGetTaskInspect(message)
    case ES_EVENT_TYPE_NOTIFY_TRACE: handleTrace(message)
    // Memory/Execution
    case ES_EVENT_TYPE_NOTIFY_MMAP: handleMmap(message)
    case ES_EVENT_TYPE_NOTIFY_MPROTECT: handleMprotect(message)
    case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME: handleProcSuspendResume(message)
    // Process introspection
    case ES_EVENT_TYPE_NOTIFY_PROC_CHECK: handleProcCheck(message)
    case ES_EVENT_TYPE_NOTIFY_PTY_GRANT: handlePTYGrant(message)
    case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE: handlePTYClose(message)
    // System changes
    case ES_EVENT_TYPE_NOTIFY_KEXTLOAD: handleKextLoad(message)
    case ES_EVENT_TYPE_NOTIFY_MOUNT: handleMount(message)
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD: handleBTMLaunchItemAdd(message)
    case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT: handleXPCConnect(message)
    case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY: handleTCCModify(message)
    // Authentication
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN: handleSSHLogin(message)
    case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED: handleXProtectMalware(message)
    // Nation-state detection
    case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN: handleIOKitOpen(message)
    case ES_EVENT_TYPE_NOTIFY_COPYFILE: handleCopyfile(message)
    case ES_EVENT_TYPE_NOTIFY_UIPC_BIND: handleUIPCBind(message)
    case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: handleUIPCConnect(message)
    case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION: handleAuthentication(message)
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN: handleSessionLogin(message)
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT: handleSessionLogout(message)
    default: break
    }

    // Periodic summary
    let now = Date()
    if now.timeIntervalSince(lastSummaryTime) > 30 {
      processLock.lock()
      let tableSize = processTable.count
      processLock.unlock()
      logger.info("[ES] exec=\(self.execCount) fork=\(self.forkCount) exit=\(self.exitCount) table=\(tableSize)")
      self.lastSummaryTime = now
    }
  }

  // MARK: - Public API

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
