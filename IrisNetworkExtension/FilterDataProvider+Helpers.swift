import Foundation
import NetworkExtension
import os.log

// MARK: - Private Helpers

extension FilterDataProvider {

    func getProcessPath(pid: Int32) -> String {
        var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let result = proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN))
        if result > 0 {
            return String(cString: pathBuffer)
        }
        return "/unknown"
    }

    func updateBytes(flow: NEFilterFlow, bytesUp: UInt64 = 0, bytesDown: UInt64 = 0) {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }

        guard let connectionId = flowToConnection[ObjectIdentifier(flow)],
              var tracker = connections[connectionId] else {
            return
        }

        tracker.bytesUp += bytesUp
        tracker.bytesDown += bytesDown
        tracker.lastActivity = Date()

        // Update local endpoint if it wasn't available initially
        if tracker.localAddress == "0.0.0.0" || tracker.localPort == 0 {
            if let socketFlow = flow as? NEFilterSocketFlow,
               let localEndpoint = socketFlow.localEndpoint as? NWHostEndpoint {
                if !localEndpoint.hostname.isEmpty && localEndpoint.hostname != "0.0.0.0" {
                    tracker.localAddress = localEndpoint.hostname
                }
                if let port = UInt16(localEndpoint.port), port != 0 {
                    tracker.localPort = port
                }
            }
        }

        connections[connectionId] = tracker
    }
}

// MARK: - Helper for audit token

func audit_token_to_pid(_ token: Data) -> Int32 {
    return token.withUnsafeBytes { ptr in
        // audit_token_t structure: pid is at offset 20 (5th 32-bit value)
        let tokenPtr = ptr.bindMemory(to: UInt32.self)
        return Int32(bitPattern: tokenPtr[5])
    }
}
