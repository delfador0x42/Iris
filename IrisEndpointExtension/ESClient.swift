//
//  ESClient.swift
//  IrisEndpointExtension
//
//  Endpoint Security client for process and file system monitoring
//
//  NOTE: To enable full ES functionality:
//  1. Link libEndpointSecurity.tbd in Xcode Build Phases
//  2. Add com.apple.developer.endpoint-security.client entitlement
//  3. Request ES entitlement from Apple (requires developer program)
//

import Foundation
import os.log

// Uncomment when ES entitlement is available:
// import EndpointSecurity

/// Endpoint Security client for monitoring system events
class ESClient {

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris.endpoint", category: "ESClient")

    /// Event callback
    private var eventHandler: ((ESEvent) -> Void)?

    /// XPC service for communicating with main app
    private var xpcService: ESXPCService?

    /// Whether the client is currently running
    private(set) var isRunning = false

    // When ES is enabled, uncomment:
    // private var client: OpaquePointer?

    // MARK: - Lifecycle

    init() {
        logger.info("ESClient initialized")
    }

    deinit {
        stop()
    }

    /// Start the Endpoint Security client
    func start() throws {
        guard !isRunning else {
            logger.warning("ESClient already running")
            return
        }

        logger.info("Starting Endpoint Security client...")

        // Start XPC service for communication with main app
        xpcService = ESXPCService()
        xpcService?.esClient = self
        xpcService?.start()

        // TODO: Initialize ES client when entitlement is available
        // This requires the com.apple.developer.endpoint-security.client entitlement
        //
        // Example ES initialization (uncomment when ready):
        //
        // var client: OpaquePointer?
        // let result = es_new_client(&client) { client, message in
        //     self.handleMessage(message)
        // }
        //
        // guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
        //     throw ESClientError.clientCreationFailed("es_new_client failed: \(result)")
        // }
        //
        // self.client = client
        //
        // // Subscribe to events
        // let events: [es_event_type_t] = [
        //     ES_EVENT_TYPE_NOTIFY_EXEC,
        //     ES_EVENT_TYPE_NOTIFY_FORK,
        //     ES_EVENT_TYPE_NOTIFY_EXIT,
        //     ES_EVENT_TYPE_NOTIFY_CREATE,
        //     ES_EVENT_TYPE_NOTIFY_RENAME,
        //     ES_EVENT_TYPE_NOTIFY_UNLINK,
        // ]
        //
        // let subscribeResult = es_subscribe(client, events, UInt32(events.count))
        // guard subscribeResult == ES_RETURN_SUCCESS else {
        //     throw ESClientError.subscriptionFailed
        // }

        isRunning = true
        logger.info("Endpoint Security client started (stub mode - awaiting entitlement)")
    }

    /// Stop the Endpoint Security client
    func stop() {
        guard isRunning else { return }

        logger.info("Stopping Endpoint Security client...")

        // TODO: Clean up ES client when enabled
        // if let client = client {
        //     es_unsubscribe_all(client)
        //     es_delete_client(client)
        //     self.client = nil
        // }

        xpcService?.stop()
        xpcService = nil

        isRunning = false
        logger.info("Endpoint Security client stopped")
    }

    /// Set the event handler callback
    func setEventHandler(_ handler: @escaping (ESEvent) -> Void) {
        self.eventHandler = handler
    }

    // MARK: - Event Handling

    // TODO: Implement when ES is enabled
    // private func handleMessage(_ message: UnsafePointer<es_message_t>) {
    //     let event = parseMessage(message)
    //     eventHandler?(event)
    // }

    // MARK: - Public API (for XPC)

    /// Get currently tracked processes
    func getTrackedProcesses() -> [ESProcessInfo] {
        // TODO: Return tracked process information
        return []
    }

    /// Check if a process is being monitored
    func isProcessMonitored(pid: Int32) -> Bool {
        // TODO: Implement process tracking
        return false
    }
}

// MARK: - Error Types

enum ESClientError: Error, LocalizedError {
    case notImplemented
    case clientCreationFailed(String)
    case subscriptionFailed
    case notRunning

    var errorDescription: String? {
        switch self {
        case .notImplemented:
            return "Endpoint Security is not yet implemented (awaiting entitlement)"
        case .clientCreationFailed(let reason):
            return "Failed to create ES client: \(reason)"
        case .subscriptionFailed:
            return "Failed to subscribe to ES events"
        case .notRunning:
            return "ES client is not running"
        }
    }
}

// MARK: - Event Types

struct ESEvent: Codable {
    let id: UUID
    let type: EventType
    let timestamp: Date
    let process: ESProcessInfo
    let details: EventDetails?

    enum EventType: String, Codable {
        case exec
        case fork
        case exit
        case create
        case rename
        case unlink
        case open
        case close
        case unknown
    }

    struct EventDetails: Codable {
        let targetPath: String?
        let newPath: String?
        let flags: UInt32?
    }
}

struct ESProcessInfo: Codable {
    let pid: Int32
    let ppid: Int32
    let path: String
    let name: String
    let teamId: String?
    let signingId: String?
    let codeSigningFlags: UInt32
    let isValid: Bool
    let isPlatformBinary: Bool
    let timestamp: Date
}
