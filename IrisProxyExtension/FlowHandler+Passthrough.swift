//
//  FlowHandler+Passthrough.swift
//  IrisProxyExtension
//
//  Generic TCP passthrough relay with metadata capture.
//  Used for all non-HTTP/HTTPS TCP flows and as HTTPS fallback.
//

import Foundation
import Network
import NetworkExtension

extension FlowHandler {

  /// Relays TCP flow data with byte counting and metadata capture.
  /// Backpressure: each write completes before the next read.
  func relayPassthrough(
    flowId: UUID, flow: NEAppProxyTCPFlow,
    host: String, port: Int, processName: String
  ) async {
    guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else {
      provider?.removeFlow(flowId)
      return
    }
    let connection = NWConnection(
      host: NWEndpoint.Host(host),
      port: nwPort,
      using: .tcp
    )

    guard await waitForConnection(connection) else {
      provider?.removeFlow(flowId)
      return
    }

    // Determine flow type: port 443 without MITM = still https, just passthrough
    let flowType: ProxyFlowType = port == 443 ? .https : .tcp
    let capturedFlow = ProxyCapturedFlow(
      id: flowId, flowType: flowType, host: host, port: port,
      processName: processName
    )
    let xpcService = self.provider?.xpcService
    xpcService?.addFlow(capturedFlow)

    let bytesOut = ByteCounter()
    let bytesIn = ByteCounter()

    await withTaskGroup(of: Void.self) { group in
      // Overall relay timeout guard
      group.addTask {
        try? await Task.sleep(nanoseconds: UInt64(Self.maxRelayDuration * 1_000_000_000))
        connection.cancel()
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
      }

      // Client → Server
      group.addTask {
        while true {
          let result: (data: Data?, error: Error?) = await withCheckedContinuation {
            continuation in
            flow.readData { data, error in
              continuation.resume(returning: (data, error))
            }
          }
          if result.error != nil { break }
          guard let data = result.data, !data.isEmpty else { break }
          bytesOut.add(Int64(data.count))
          do {
            try await Self.sendToServer(connection, data: data)
          } catch {
            flow.closeReadWithError(nil)
            break
          }
        }
        connection.cancel()
      }

      // Server → Client
      group.addTask {
        while true {
          do {
            let data = try await Self.receiveFromServer(connection)
            guard !data.isEmpty else { continue }
            bytesIn.add(Int64(data.count))
            let writeError: Error? = await withCheckedContinuation { continuation in
              flow.write(data) { error in continuation.resume(returning: error) }
            }
            if writeError != nil { break }
          } catch {
            flow.closeWriteWithError(nil)
            break
          }
        }
      }
    }

    connection.cancel()
    xpcService?.completeFlow(
      flowId, bytesIn: bytesIn.value, bytesOut: bytesOut.value, error: nil)
    provider?.removeFlow(flowId)
  }
}

/// Thread-safe byte counter for relay tasks.
final class ByteCounter: @unchecked Sendable {
  private var _value: Int64 = 0
  private let lock = NSLock()

  var value: Int64 {
    lock.lock()
    defer { lock.unlock() }
    return _value
  }

  func add(_ n: Int64) {
    lock.lock()
    _value += n
    lock.unlock()
  }
}
