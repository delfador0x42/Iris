import Foundation
import EndpointSecurity
import os.log

/// Endpoint Security client for real-time process monitoring.
/// Subscribes to EXEC/FORK/EXIT events and maintains a live process table.
/// XPC polls snapshot this table for the app.
class ESClient {

    private let logger = Logger(subsystem: "com.wudan.iris.endpoint", category: "ESClient")

    /// The ES client handle
    private var client: OpaquePointer?

    /// Live process table: pid → process info
    private var processTable: [pid_t: ESProcessInfo] = [:]
    private let processLock = NSLock()

    /// Serial queue for processing ES events off the callback thread
    private let processingQueue = DispatchQueue(label: "com.wudan.iris.endpoint.processing")

    /// XPC service for communication with main app
    private(set) var xpcService: ESXPCService?

    /// Whether the client is currently running
    private(set) var isRunning = false

    /// Error message if ES client failed to start
    private(set) var startupError: String?

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

        // Start XPC service first
        xpcService = ESXPCService()
        xpcService?.esClient = self
        xpcService?.start()

        // Create ES client
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

        // Mute our own process to prevent feedback loops
        var selfToken = auditTokenForSelf()
        es_mute_process(esClient, &selfToken)
        logger.info("Muted own process (PID \(getpid()))")

        // Subscribe to process lifecycle events
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

        // Seed process table with currently running processes
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

    /// Called from ES dispatch thread — must be fast
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

    /// Process a copied ES message on our serial queue
    private func processEvent(_ message: UnsafeMutablePointer<es_message_t>) {
        switch message.pointee.event_type {

        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let proc = message.pointee.process.pointee
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

            // Create stub entry — will be replaced by EXEC if child calls execve
            let stub = ESProcessInfo(
                id: UUID(),
                pid: childPid,
                ppid: parentPid,
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

    // MARK: - Data Extraction

    /// Extract full process info from an es_process_t (typically the exec target)
    private func extractProcessInfo(
        from process: es_process_t,
        event: UnsafeMutablePointer<es_message_t>
    ) -> ESProcessInfo {
        let pid = audit_token_to_pid(process.audit_token)
        let ppid = process.ppid
        let path = esStringToSwift(process.executable.pointee.path)
        let name = URL(fileURLWithPath: path).lastPathComponent

        // Extract arguments from EXEC event
        var arguments: [String] = []
        let argCount = es_exec_arg_count(&event.pointee.event.exec)
        for i in 0..<argCount {
            let arg = es_exec_arg(&event.pointee.event.exec, i)
            arguments.append(esStringToSwift(arg))
        }

        let uid = audit_token_to_euid(process.audit_token)
        let gid = audit_token_to_egid(process.audit_token)
        let csInfo = extractCodeSigningInfo(from: process)

        return ESProcessInfo(
            id: UUID(),
            pid: pid,
            ppid: ppid,
            path: path,
            name: name,
            arguments: arguments,
            userId: uid,
            groupId: gid,
            codeSigningInfo: csInfo,
            timestamp: Date()
        )
    }

    /// Extract code signing info from es_process_t
    private func extractCodeSigningInfo(from process: es_process_t) -> ESProcessInfo.CodeSigningInfo {
        let signingId = esStringToSwift(process.signing_id)
        let teamId = esStringToSwift(process.team_id)
        let flags = process.codesigning_flags
        let isPlatform = process.is_platform_binary

        // Apple-signed: platform binary or com.apple.* signing ID with valid signature
        let isApple = isPlatform || (signingId.hasPrefix("com.apple.") && teamId.isEmpty)

        return ESProcessInfo.CodeSigningInfo(
            teamId: teamId.isEmpty ? nil : teamId,
            signingId: signingId.isEmpty ? nil : signingId,
            flags: flags,
            isAppleSigned: isApple,
            isPlatformBinary: isPlatform
        )
    }

    // MARK: - String Bridging

    /// Convert ES string token to Swift String
    private func esStringToSwift(_ token: es_string_token_t) -> String {
        guard token.length > 0, let data = token.data else { return "" }
        return String(bytesNoCopy: UnsafeMutableRawPointer(mutating: data),
                      length: token.length,
                      encoding: .utf8,
                      freeWhenDone: false) ?? ""
    }

    // MARK: - Process Table Seeding

    /// Seed the process table with currently running processes via sysctl.
    /// ES only sends events for NEW activity after subscription.
    private func seedProcessTable() {
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

            // Get code signing info via SecStaticCode
            let csInfo = getCodeSigningInfoForPath(path)

            processTable[pid] = ESProcessInfo(
                id: UUID(),
                pid: pid,
                ppid: ppid,
                path: path,
                name: name,
                arguments: [],
                userId: uid,
                groupId: gid,
                codeSigningInfo: csInfo,
                timestamp: Date()
            )
            seeded += 1
        }
        processLock.unlock()

        logger.info("Seeded process table with \(seeded) existing processes")
    }

    /// Get process path via proc_pidpath
    private func getProcessPath(_ pid: pid_t) -> String {
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
        defer { buf.deallocate() }
        let len = proc_pidpath(pid, buf, UInt32(MAXPATHLEN))
        guard len > 0 else { return "" }
        return String(cString: buf)
    }

    /// Get code signing info for a path using Security framework
    private func getCodeSigningInfoForPath(_ path: String) -> ESProcessInfo.CodeSigningInfo? {
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL

        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return nil
        }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else {
            return nil
        }

        let teamId = dict[kSecCodeInfoTeamIdentifier as String] as? String
        let signingId = dict[kSecCodeInfoIdentifier as String] as? String
        let flags = (dict[kSecCodeInfoFlags as String] as? UInt32) ?? 0
        let isPlatform = (flags & 0x4000) != 0  // CS_PLATFORM_BINARY

        let isApple = isPlatform || (signingId?.hasPrefix("com.apple.") == true && teamId == nil)

        return ESProcessInfo.CodeSigningInfo(
            teamId: teamId,
            signingId: signingId,
            flags: flags,
            isAppleSigned: isApple,
            isPlatformBinary: isPlatform
        )
    }

    // MARK: - Audit Token

    /// Get our own audit token for muting
    private func auditTokenForSelf() -> audit_token_t {
        var token = audit_token_t()
        var size = UInt32(MemoryLayout<audit_token_t>.size)
        let kr = task_info(
            mach_task_self_,
            task_flavor_t(TASK_AUDIT_TOKEN),
            withUnsafeMutablePointer(to: &token) {
                $0.withMemoryRebound(to: integer_t.self, capacity: Int(size) / MemoryLayout<integer_t>.size) { $0 }
            },
            &size
        )
        if kr != KERN_SUCCESS {
            logger.warning("Failed to get own audit token, using empty token")
        }
        return token
    }

    // MARK: - Public API (for XPC)

    /// Get snapshot of all tracked processes
    func getTrackedProcesses() -> [ESProcessInfo] {
        processLock.lock()
        let snapshot = Array(processTable.values)
        processLock.unlock()
        return snapshot
    }

    /// Get a specific process by PID
    func getProcess(pid: pid_t) -> ESProcessInfo? {
        processLock.lock()
        let process = processTable[pid]
        processLock.unlock()
        return process
    }

    // MARK: - Helpers

    private func esClientErrorDescription(_ result: es_new_client_result_t) -> String {
        switch result {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return "Missing com.apple.developer.endpoint-security.client entitlement"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return "Not permitted — grant Full Disk Access or approve in System Settings"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return "Not running as root or system extension"
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return "Too many ES clients — max reached"
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            return "Internal ES error"
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            return "Invalid argument to es_new_client"
        default:
            return "Unknown error (\(result.rawValue))"
        }
    }
}

// MARK: - Error Types

enum ESClientError: Error, LocalizedError {
    case clientCreationFailed(String)
    case subscriptionFailed
    case notRunning

    var errorDescription: String? {
        switch self {
        case .clientCreationFailed(let reason):
            return "Failed to create ES client: \(reason)"
        case .subscriptionFailed:
            return "Failed to subscribe to ES events"
        case .notRunning:
            return "ES client is not running"
        }
    }
}

// MARK: - Process Info Model (matches ProcessInfo Codable shape)

struct ESProcessInfo: Codable {
    let id: UUID
    let pid: Int32
    let ppid: Int32
    let path: String
    let name: String
    let arguments: [String]
    let userId: UInt32
    let groupId: UInt32
    let codeSigningInfo: CodeSigningInfo?
    let timestamp: Date

    struct CodeSigningInfo: Codable {
        let teamId: String?
        let signingId: String?
        let flags: UInt32
        let isAppleSigned: Bool
        let isPlatformBinary: Bool
    }
}
