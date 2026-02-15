//
//  FlowHandler+UDPRelay.swift
//  IrisProxyExtension
//
//  UDP datagram relay: forwards datagrams bidirectionally with byte counting.
//  Each unique destination endpoint gets its own NWConnection.
//

import Foundation
import Network
import NetworkExtension
import os.log

extension FlowHandler {

  /// Relays UDP datagrams with metadata capture.
  func relayUDP(
    flowId: UUID, flow: NEAppProxyUDPFlow,
    processName: String
  ) async {
    // UDP flows don't have a single remote endpoint — each datagram has its own.
    // We create NWConnections on-demand per destination.
    let connections = UDPConnectionPool()
    let bytesOut = ByteCounter()
    let bytesIn = ByteCounter()
    let xpcService = self.provider?.xpcService

    // We'll capture the first datagram's destination for the flow entry
    let flowReported = AtomicFlag()

    await withTaskGroup(of: Void.self) { group in
      // Overall relay timeout
      group.addTask {
        try? await Task.sleep(nanoseconds: UInt64(Self.maxRelayDuration * 1_000_000_000))
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
        await connections.cancelAll()
      }

      // Client → Server: read datagrams from the flow, forward to real destinations
      group.addTask { [weak self] in
        guard let self = self else { return }
        while true {
          let result = await Self.readDatagrams(from: flow)
          guard let datagrams = result.datagrams, !datagrams.isEmpty else { break }
          let endpoints = result.endpoints

          for (i, datagram) in datagrams.enumerated() {
            guard let endpoint = endpoints[safe: i] as? NWHostEndpoint else { continue }
            let host = endpoint.hostname
            let port = Int(endpoint.port) ?? 0

            // Report the first datagram's destination as the flow metadata
            if flowReported.trySet() {
              let capturedFlow = ProxyCapturedFlow(
                id: flowId, flowType: .udp, host: host, port: port,
                processName: processName
              )
              xpcService?.addFlow(capturedFlow)
            }

            bytesOut.add(Int64(datagram.count))

            // Get or create connection for this destination
            let conn = await connections.connection(for: host, port: port)
            conn.send(
              content: datagram,
              completion: .contentProcessed { error in
                if let error = error {
                  self.logger.debug(
                    "UDP send error to \(host):\(port): \(error.localizedDescription)")
                }
              })
          }
        }
        await connections.cancelAll()
      }

      // Server → Client: receive from all connections, write back to flow
      // For UDP we read from the most recently used connection
      // This is simplified — in practice each connection's responses go back on the flow
      group.addTask { [weak self] in
        guard self != nil else { return }
        while !Task.isCancelled {
          guard let active = await connections.anyActive() else {
            try? await Task.sleep(nanoseconds: 100_000_000)
            continue
          }
          do {
            let data = try await Self.receiveUDP(active.connection)
            guard !data.isEmpty else { continue }
            bytesIn.add(Int64(data.count))
            // Reconstruct NWHostEndpoint (NetworkExtension type) for writeDatagrams
            let replyEndpoint = NWHostEndpoint(hostname: active.host, port: active.port)
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
              flow.writeDatagrams([data], sentBy: [replyEndpoint]) { _ in
                continuation.resume()
              }
            }
          } catch {
            break
          }
        }
      }
    }

    await connections.cancelAll()
    // Only complete if we actually reported the flow
    if !flowReported.trySet() {
      xpcService?.completeFlow(
        flowId, bytesIn: bytesIn.value, bytesOut: bytesOut.value, error: nil)
    }
    provider?.removeUDPFlow(flowId)
  }

  // MARK: - UDP Helpers

  static func readDatagrams(from flow: NEAppProxyUDPFlow) async -> (
    datagrams: [Data]?, endpoints: [Any]
  ) {
    await withCheckedContinuation { continuation in
      flow.readDatagrams { datagrams, endpoints, error in
        if error != nil || datagrams == nil {
          continuation.resume(returning: (nil, []))
        } else {
          continuation.resume(returning: (datagrams, endpoints ?? []))
        }
      }
    }
  }

  static func receiveUDP(_ connection: NWConnection) async throws -> Data {
    try await withCheckedThrowingContinuation {
      (continuation: CheckedContinuation<Data, Error>) in
      connection.receiveMessage { data, _, isComplete, error in
        if let error = error {
          continuation.resume(throwing: error)
        } else if let data = data, !data.isEmpty {
          continuation.resume(returning: data)
        } else if isComplete {
          continuation.resume(throwing: TLSSessionError.connectionClosed)
        } else {
          continuation.resume(returning: Data())
        }
      }
    }
  }
}

// MARK: - UDP Connection Pool

/// Manages NWConnections for UDP relay, one per unique destination.
actor UDPConnectionPool {
  private var connections: [String: NWConnection] = [:]

  func connection(for host: String, port: Int) -> NWConnection {
    let key = "\(host):\(port)"
    if let existing = connections[key] { return existing }
    let conn = NWConnection(
      host: NWEndpoint.Host(host),
      port: NWEndpoint.Port(rawValue: UInt16(clamping: port))!,
      using: .udp
    )
    conn.start(queue: .global(qos: .userInitiated))
    connections[key] = conn
    return conn
  }

  func anyActive() -> (connection: NWConnection, host: String, port: String)? {
    for (key, conn) in connections where conn.state == .ready {
      let parts = key.split(separator: ":", maxSplits: 1)
      guard parts.count == 2 else { continue }
      return (conn, String(parts[0]), String(parts[1]))
    }
    return nil
  }

  func cancelAll() {
    for (_, conn) in connections { conn.cancel() }
    connections.removeAll()
  }
}

// MARK: - Safe Array Subscript

extension Collection {
  subscript(safe index: Index) -> Element? {
    indices.contains(index) ? self[index] : nil
  }
}
