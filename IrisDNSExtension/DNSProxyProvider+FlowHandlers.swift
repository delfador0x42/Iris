//
//  DNSProxyProvider+FlowHandlers.swift
//  IrisDNSExtension
//
//  UDP and TCP DNS flow handling and DoH query forwarding.
//

import Foundation
import NetworkExtension
import os.log

extension DNSProxyProvider {

    // MARK: - UDP DNS Flow

    func handleDNSFlow(_ flow: NEAppProxyUDPFlow) async {
        let openError: Error? = await withCheckedContinuation { continuation in
            flow.open(withLocalEndpoint: nil) { error in continuation.resume(returning: error) }
        }
        if let error = openError {
            logger.error("Failed to open UDP DNS flow: \(error.localizedDescription)")
            return
        }
        await readDNSDatagrams(from: flow)
    }

    func readDNSDatagrams(from flow: NEAppProxyUDPFlow) async {
        while true {
            let result = await withCheckedContinuation { (continuation: CheckedContinuation<(datagrams: [Data]?, endpoints: [NWEndpoint]?, error: Error?), Never>) in
                flow.readDatagrams { datagrams, endpoints, error in
                    continuation.resume(returning: (datagrams, endpoints, error))
                }
            }

            if let error = result.error {
                let nsError = error as NSError
                if nsError.code != NEAppProxyFlowError.notConnected.rawValue {
                    logger.error("DNS flow read error: \(error.localizedDescription)")
                }
                break
            }
            guard let datagrams = result.datagrams, let endpoints = result.endpoints, !datagrams.isEmpty else { break }

            // Use min() to guard against count mismatch between arrays
            let count = min(datagrams.count, endpoints.count)
            for index in 0..<count {
                await processDNSDatagram(datagrams[index], from: flow, originalEndpoint: endpoints[index])
            }
        }
    }

    func processDNSDatagram(_ datagram: Data, from flow: NEAppProxyUDPFlow, originalEndpoint: NWEndpoint) async {
        guard datagram.count >= 12 else { return }
        let startTime = CFAbsoluteTimeGetCurrent()
        incrementTotalQueries()
        let queryInfo = parseDNSQueryInfo(datagram)
        logger.debug("DNS query: \(queryInfo.domain) (\(queryInfo.type))")

        do {
            let responseData = try await dohClient.query(datagram)
            guard responseData.count <= 65535 else {
                logger.warning("DNS response oversized: \(responseData.count) bytes, dropping")
                return
            }
            let elapsed = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
            addLatency(elapsed)
            let responseInfo = parseDNSResponseInfo(responseData)

            recordQuery(
                domain: queryInfo.domain, type: queryInfo.type,
                processName: flow.metaData.sourceAppSigningIdentifier.components(separatedBy: ".").last,
                responseCode: responseInfo.responseCode,
                answers: responseInfo.answers, ttl: responseInfo.ttl, latencyMs: elapsed
            )

            flow.writeDatagrams([responseData], sentBy: [originalEndpoint]) { error in
                if let error = error {
                    Logger(subsystem: "com.wudan.iris.dns", category: "DNSProxyProvider")
                        .error("Failed to write DNS response: \(error.localizedDescription)")
                }
            }
        } catch {
            incrementFailedQueries()
            logger.error("DoH query failed for \(queryInfo.domain): \(error.localizedDescription)")
            recordQuery(
                domain: queryInfo.domain, type: queryInfo.type,
                processName: flow.metaData.sourceAppSigningIdentifier.components(separatedBy: ".").last,
                responseCode: "SERVFAIL", answers: [], ttl: nil,
                latencyMs: (CFAbsoluteTimeGetCurrent() - startTime) * 1000
            )
            if let servfailResponse = buildServfailResponse(for: datagram) {
                flow.writeDatagrams([servfailResponse], sentBy: [originalEndpoint]) { _ in }
            }
        }
    }

    // MARK: - TCP DNS Flow

    func handleTCPDNSFlow(_ flow: NEAppProxyTCPFlow) async {
        let openError: Error? = await withCheckedContinuation { continuation in
            flow.open(withLocalEndpoint: nil) { error in continuation.resume(returning: error) }
        }
        if let error = openError {
            logger.error("Failed to open TCP DNS flow: \(error.localizedDescription)")
            return
        }
        await readTCPDNSData(from: flow)
    }

    func readTCPDNSData(from flow: NEAppProxyTCPFlow) async {
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
            // Cap buffer to prevent unbounded growth from partial messages
            if buffer.count > 131072 { buffer.removeAll(); break }

            while buffer.count >= 2 {
                let msgLength = Int(buffer[0]) << 8 | Int(buffer[1])
                // RFC 1035: DNS messages must be > 0 and <= 65535 bytes
                guard msgLength > 0 && msgLength <= 65535 else {
                    buffer.removeAll()
                    break
                }
                guard buffer.count >= 2 + msgLength else { break }
                let dnsMessage = Data(buffer[2..<(2 + msgLength)])
                buffer.removeFirst(2 + msgLength)
                await processTCPDNSDatagram(dnsMessage, flow: flow)
            }
        }
    }

    func processTCPDNSDatagram(_ datagram: Data, flow: NEAppProxyTCPFlow) async {
        let startTime = CFAbsoluteTimeGetCurrent()
        incrementTotalQueries()
        let queryInfo = parseDNSQueryInfo(datagram)
        logger.debug("TCP DNS query: \(queryInfo.domain) (\(queryInfo.type))")

        do {
            let responseData = try await dohClient.query(datagram)
            // TCP DNS max message size is 65535 (2-byte length prefix)
            guard responseData.count <= 65535 else {
                logger.warning("TCP DNS response oversized: \(responseData.count) bytes, dropping")
                return
            }
            let elapsed = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
            addLatency(elapsed)
            let responseInfo = parseDNSResponseInfo(responseData)

            recordQuery(
                domain: queryInfo.domain, type: queryInfo.type,
                processName: flow.metaData.sourceAppSigningIdentifier.components(separatedBy: ".").last,
                responseCode: responseInfo.responseCode,
                answers: responseInfo.answers, ttl: responseInfo.ttl, latencyMs: elapsed
            )

            var tcpResponse = Data()
            let length = UInt16(responseData.count)
            tcpResponse.append(UInt8(length >> 8))
            tcpResponse.append(UInt8(length & 0xFF))
            tcpResponse.append(responseData)

            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                flow.write(tcpResponse) { _ in continuation.resume() }
            }
        } catch {
            incrementFailedQueries()
            logger.error("DoH query failed for TCP \(queryInfo.domain): \(error.localizedDescription)")
            recordQuery(
                domain: queryInfo.domain, type: queryInfo.type,
                processName: flow.metaData.sourceAppSigningIdentifier.components(separatedBy: ".").last,
                responseCode: "SERVFAIL", answers: [], ttl: nil,
                latencyMs: (CFAbsoluteTimeGetCurrent() - startTime) * 1000
            )
            if let servfailResponse = buildServfailResponse(for: datagram) {
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
