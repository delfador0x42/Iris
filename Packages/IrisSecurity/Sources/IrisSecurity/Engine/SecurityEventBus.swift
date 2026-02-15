import Foundation
import os.log

/// Event bus that polls XPC extensions for new events and feeds
/// them to the DetectionEngine. Uses delta-fetch (sequence numbers)
/// to avoid re-processing events.
public actor SecurityEventBus {
    public static let shared = SecurityEventBus()

    private let logger = Logger(subsystem: "com.wudan.iris", category: "EventBus")
    private var esSequence: UInt64 = 0
    private var isRunning = false
    private var pollTask: Task<Void, Never>?

    /// Start polling all event sources
    public func start() {
        guard !isRunning else { return }
        isRunning = true

        pollTask = Task { [weak self] in
            guard let self else { return }
            await self.pollLoop()
        }
        logger.info("[BUS] Event bus started")
    }

    /// Stop polling
    public func stop() {
        isRunning = false
        pollTask?.cancel()
        pollTask = nil
        logger.info("[BUS] Event bus stopped")
    }

    private func pollLoop() async {
        while isRunning && !Task.isCancelled {
            await pollEndpointSecurity()
            try? await Task.sleep(nanoseconds: 1_000_000_000) // 1s interval
        }
    }

    /// Poll ES extension for new security events via XPC
    private func pollEndpointSecurity() async {
        let serviceName = "99HGW2AR62.com.wudan.iris.endpoint.xpc"
        let connection = NSXPCConnection(machServiceName: serviceName)

        // Import the protocol dynamically — the protocol is in Shared/
        let interface = NSXPCInterface(with: NSObjectProtocol.self)
        connection.remoteObjectInterface = interface
        connection.resume()

        // For now, the event bus uses a lightweight poll.
        // Full integration requires importing EndpointXPCProtocol which is
        // in the Shared target. We'll bridge via the ProcessStore in Phase 7.
        connection.invalidate()
    }

    /// Feed events from an external source (e.g. ProcessStore polling)
    public func ingest(_ events: [SecurityEvent]) async {
        guard !events.isEmpty else { return }
        await DetectionEngine.shared.processBatch(events)
    }

    /// Feed a single event
    public func ingest(_ event: SecurityEvent) async {
        await DetectionEngine.shared.process(event)
    }
}
