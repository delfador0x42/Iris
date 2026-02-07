//
//  FlowHandler+Passthrough.swift
//  IrisProxyExtension
//
//  Pass-through relay: forwards traffic without parsing.
//  Used as fallback when TLS MITM is unavailable.
//

import Foundation
import Network
import NetworkExtension

extension FlowHandler {

    /// Relays flow data without parsing.
    func relayPassthrough(
        flowId: UUID, flow: NEAppProxyTCPFlow,
        host: String, port: Int
    ) async {
        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: UInt16(port)),
            using: .tcp
        )

        guard await waitForConnection(connection) else {
            provider?.removeFlow(flowId)
            return
        }

        await withTaskGroup(of: Void.self) { group in
            // Client → Server
            group.addTask {
                while true {
                    let result: (data: Data?, error: Error?) = await withCheckedContinuation { continuation in
                        flow.readData { data, error in
                            continuation.resume(returning: (data, error))
                        }
                    }
                    if result.error != nil { break }
                    guard let data = result.data, !data.isEmpty else { break }
                    do {
                        try await Self.sendToServer(connection, data: data)
                    } catch { break }
                }
                connection.cancel()
            }

            // Server → Client
            group.addTask {
                while true {
                    do {
                        let data = try await Self.receiveFromServer(connection)
                        guard !data.isEmpty else { continue }
                        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                            flow.write(data) { _ in continuation.resume() }
                        }
                    } catch {
                        flow.closeWriteWithError(nil)
                        break
                    }
                }
            }
        }

        connection.cancel()
        provider?.removeFlow(flowId)
    }
}
