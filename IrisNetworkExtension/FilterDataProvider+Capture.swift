import Foundation
import NetworkExtension
import os.log

// MARK: - Raw Data Capture

extension FilterDataProvider {

    /// Append raw bytes to a connection's capture buffer.
    /// Called from handleOutboundData/handleInboundData on every data chunk.
    func appendCaptureData(flow: NEFilterFlow, outbound: Data? = nil, inbound: Data? = nil) {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }

        guard let connectionId = flowToConnection[ObjectIdentifier(flow)],
              var tracker = connections[connectionId] else { return }

        if let data = outbound {
            tracker.rawOutbound.append(data)
            totalCaptureBytes += data.count
        }
        if let data = inbound {
            tracker.rawInbound.append(data)
            totalCaptureBytes += data.count
        }

        connections[connectionId] = tracker

        if totalCaptureBytes > captureMemoryBudget {
            evictOldestCaptureData()
        }
    }

    /// Evict raw data from oldest connections until under budget.
    /// Must be called while holding connectionsLock.
    private func evictOldestCaptureData() {
        while totalCaptureBytes > captureMemoryBudget {
            // Find oldest connection that has raw data
            guard let oldest = connections
                .filter({ $0.value.rawOutbound.count + $0.value.rawInbound.count > 0 })
                .min(by: { $0.value.lastActivity < $1.value.lastActivity })
            else { break }

            let freed = connections[oldest.key]!.rawOutbound.count +
                        connections[oldest.key]!.rawInbound.count
            connections[oldest.key]!.rawOutbound = Data()
            connections[oldest.key]!.rawInbound = Data()
            totalCaptureBytes -= freed

            logger.debug("Evicted \(freed) capture bytes from connection \(oldest.key)")
        }
    }

    /// Get raw captured data for a specific connection (called from XPC).
    func getRawData(for connectionId: UUID) -> (Data?, Data?) {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }

        guard let tracker = connections[connectionId] else { return (nil, nil) }
        let out = tracker.rawOutbound.isEmpty ? nil : tracker.rawOutbound
        let inb = tracker.rawInbound.isEmpty ? nil : tracker.rawInbound
        return (out, inb)
    }

    /// Get capture statistics for XPC status reporting.
    func getCaptureStats() -> [String: Any] {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }

        let connectionsWithData = connections.values
            .filter { $0.rawOutbound.count + $0.rawInbound.count > 0 }
            .count

        return [
            "totalCaptureBytes": totalCaptureBytes,
            "captureMemoryBudget": captureMemoryBudget,
            "connectionsWithData": connectionsWithData,
            "totalConnections": connections.count
        ]
    }
}
