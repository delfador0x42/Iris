import Foundation
import NetworkExtension
import os.log

// MARK: - Raw Data Capture

extension FilterDataProvider {

    /// Append a timestamped capture segment to a connection's buffer.
    /// Called from handleOutboundData/handleInboundData on every data chunk.
    func appendCaptureData(flow: NEFilterFlow, outbound: Data? = nil, inbound: Data? = nil) {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }

        guard let connectionId = flowToConnection[ObjectIdentifier(flow)],
              var tracker = connections[connectionId] else { return }

        let now = Date()

        if let data = outbound {
            tracker.captureSegments.append(CaptureSegment(timestamp: now, direction: .outbound, data: data))
            totalCaptureBytes += data.count
        }
        if let data = inbound {
            tracker.captureSegments.append(CaptureSegment(timestamp: now, direction: .inbound, data: data))
            totalCaptureBytes += data.count
        }

        connections[connectionId] = tracker

        if totalCaptureBytes > captureMemoryBudget {
            evictOldestCaptureData()
        }
    }

    /// Evict capture data from oldest connections until under budget.
    /// Must be called while holding connectionsLock.
    private func evictOldestCaptureData() {
        while totalCaptureBytes > captureMemoryBudget {
            guard let oldest = connections
                .filter({ !$0.value.captureSegments.isEmpty })
                .min(by: { $0.value.lastActivity < $1.value.lastActivity })
            else { break }

            let freed = connections[oldest.key]!.captureSegments.reduce(0) { $0 + $1.byteCount }
            connections[oldest.key]!.captureSegments.removeAll()
            totalCaptureBytes -= freed

            logger.debug("Evicted \(freed) capture bytes from connection \(oldest.key)")
        }
    }

    /// Get conversation segments for a specific connection (called from XPC).
    func getConversation(for connectionId: UUID) -> [CaptureSegment] {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }

        return connections[connectionId]?.captureSegments ?? []
    }

    /// Get raw captured data as blobs (legacy compatibility for HTTPRawDetailView).
    func getRawData(for connectionId: UUID) -> (Data?, Data?) {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }

        guard let tracker = connections[connectionId] else { return (nil, nil) }

        var outbound = Data()
        var inbound = Data()
        for segment in tracker.captureSegments {
            switch segment.direction {
            case .outbound: outbound.append(segment.data)
            case .inbound: inbound.append(segment.data)
            }
        }
        return (outbound.isEmpty ? nil : outbound, inbound.isEmpty ? nil : inbound)
    }

    /// Get capture statistics for XPC status reporting.
    func getCaptureStats() -> [String: Any] {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }

        let connectionsWithData = connections.values
            .filter { !$0.captureSegments.isEmpty }
            .count

        return [
            "totalCaptureBytes": totalCaptureBytes,
            "captureMemoryBudget": captureMemoryBudget,
            "connectionsWithData": connectionsWithData,
            "totalConnections": connections.count
        ]
    }
}
