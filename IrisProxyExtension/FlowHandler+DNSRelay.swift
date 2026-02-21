//
//  FlowHandler+DNSRelay.swift
//  IrisProxyExtension
//
//  DNS-over-HTTPS handling for port 53 traffic intercepted by the proxy.
//  UDP DNS: handled inline per-datagram in the UDP relay (handleDNSDatagram).
//  TCP DNS: handled as a dedicated flow (relayDNSTCP) when port is 53.
//  Records all DNS queries for the main app's DNS monitor.
//

import Foundation
import Network
import NetworkExtension
import os.log

extension FlowHandler {

  // MARK: - UDP DNS (inline per-datagram)

  /// Handles a single DNS datagram from the UDP relay.
  /// Called inline when a datagram's destination is port 53.
  func handleDNSDatagram(
    _ datagram: Data, from flow: NEAppProxyUDPFlow,
    endpoint: NWHostEndpoint, processName: String,
    xpcService: ProxyXPCService?, bytesIn: ByteCounter
  ) async {
    let startTime = CFAbsoluteTimeGetCurrent()
    let queryInfo = parseDNSQueryInfo(datagram)
    logger.debug("DNS query: \(queryInfo.domain) (\(queryInfo.type)) from \(processName)")

    do {
      let result = try await dohClient.query(datagram)
      guard result.data.count <= 65535 else {
        logger.warning("DNS response oversized: \(result.data.count) bytes, dropping")
        return
      }
      let elapsed = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
      let responseInfo = parseDNSResponseInfo(result.data)
      bytesIn.add(Int64(result.data.count))

      xpcService?.recordDNSQuery(
        domain: queryInfo.domain, type: queryInfo.type,
        processName: processName,
        responseCode: responseInfo.responseCode,
        answers: responseInfo.answers, ttl: responseInfo.ttl,
        latencyMs: elapsed, isEncrypted: result.isEncrypted
      )

      flow.writeDatagrams([result.data], sentBy: [endpoint]) { error in
        if let error = error {
          Logger(subsystem: "com.wudan.iris.proxy", category: "FlowHandler")
            .error("Failed to write DNS response: \(error.localizedDescription)")
        }
      }
    } catch {
      let elapsed = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
      logger.error("DoH query failed for \(queryInfo.domain): \(error.localizedDescription)")

      xpcService?.recordDNSQuery(
        domain: queryInfo.domain, type: queryInfo.type,
        processName: processName,
        responseCode: "SERVFAIL", answers: [], ttl: nil,
        latencyMs: elapsed, isEncrypted: false
      )

      if let servfailResponse = buildServfailResponse(for: datagram) {
        flow.writeDatagrams([servfailResponse], sentBy: [endpoint]) { _ in }
      }
    }
  }

  // MARK: - TCP DNS (dedicated flow handler)

  /// Handles a TCP DNS flow: reads length-prefixed DNS messages, forwards via DoH.
  func relayDNSTCP(
    flowId: UUID, flow: NEAppProxyTCPFlow,
    host: String, port: Int, processName: String
  ) async {
    let xpcService = self.provider?.xpcService

    let capturedFlow = ProxyCapturedFlow(
      id: flowId, flowType: .tcp, host: host, port: port,
      processName: processName
    )
    xpcService?.addFlow(capturedFlow)

    var bytesOut: Int64 = 0
    var bytesIn: Int64 = 0
    var buffer = Data()

    while true {
      let result: (data: Data?, error: Error?) = await withCheckedContinuation { continuation in
        flow.readData { data, error in continuation.resume(returning: (data, error)) }
      }

      if let error = result.error {
        let nsError = error as NSError
        if nsError.code != NEAppProxyFlowError.notConnected.rawValue {
          logger.error("TCP DNS flow read error: \(error.localizedDescription)")
        }
        break
      }
      guard let data = result.data, !data.isEmpty else { break }
      buffer.append(data)
      if buffer.count > 131072 { buffer.removeAll(); break }

      while buffer.count >= 2 {
        let msgLength = Int(buffer[0]) << 8 | Int(buffer[1])
        guard msgLength > 0 && msgLength <= 65535 else {
          buffer.removeAll()
          break
        }
        guard buffer.count >= 2 + msgLength else { break }
        let dnsMessage = Data(buffer[2..<(2 + msgLength)])
        buffer.removeFirst(2 + msgLength)

        bytesOut += Int64(2 + msgLength)

        let startTime = CFAbsoluteTimeGetCurrent()
        let queryInfo = parseDNSQueryInfo(dnsMessage)
        logger.debug("TCP DNS query: \(queryInfo.domain) (\(queryInfo.type))")

        do {
          let result = try await dohClient.query(dnsMessage)
          guard result.data.count <= 65535 else {
            logger.warning("TCP DNS response oversized: \(result.data.count) bytes")
            continue
          }
          let elapsed = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
          let responseInfo = parseDNSResponseInfo(result.data)

          xpcService?.recordDNSQuery(
            domain: queryInfo.domain, type: queryInfo.type,
            processName: processName,
            responseCode: responseInfo.responseCode,
            answers: responseInfo.answers, ttl: responseInfo.ttl,
            latencyMs: elapsed, isEncrypted: result.isEncrypted
          )

          var tcpResponse = Data()
          let length = UInt16(result.data.count)
          tcpResponse.append(UInt8(length >> 8))
          tcpResponse.append(UInt8(length & 0xFF))
          tcpResponse.append(result.data)

          bytesIn += Int64(tcpResponse.count)

          await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            flow.write(tcpResponse) { _ in continuation.resume() }
          }
        } catch {
          let elapsed = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
          logger.error("DoH query failed for TCP \(queryInfo.domain): \(error.localizedDescription)")

          xpcService?.recordDNSQuery(
            domain: queryInfo.domain, type: queryInfo.type,
            processName: processName,
            responseCode: "SERVFAIL", answers: [], ttl: nil,
            latencyMs: elapsed, isEncrypted: false
          )

          if let servfailResponse = buildServfailResponse(for: dnsMessage) {
            var tcpResponse = Data()
            let length = UInt16(servfailResponse.count)
            tcpResponse.append(UInt8(length >> 8))
            tcpResponse.append(UInt8(length & 0xFF))
            tcpResponse.append(servfailResponse)
            flow.write(tcpResponse) { _ in }
          }
        }
      }
    }

    xpcService?.completeFlow(flowId, bytesIn: bytesIn, bytesOut: bytesOut, error: nil)
    provider?.removeFlow(flowId)
  }
}
