//
//  FlowHandler+MITMRelay.swift
//  IrisProxyExtension
//
//  MITM relay: decrypts HTTPS traffic between client TLS session and server NWConnection,
//  parsing and capturing HTTP flows for the UI.
//

import Foundation
import Network
import NetworkExtension
import os.log

extension FlowHandler {

    /// Relays decrypted HTTP between client TLS session and server NWConnection.
    func relayMITM(
        flowId: UUID, flow: NEAppProxyTCPFlow,
        clientTLS: TLSSession, serverConnection: NWConnection,
        host: String, port: Int, processName: String
    ) async {
        let startTime = CFAbsoluteTimeGetCurrent()
        let state = RelayState()
        let xpcService = self.provider?.xpcService

        await withTaskGroup(of: Void.self) { group in
            // Overall relay timeout guard
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(Self.maxRelayDuration * 1_000_000_000))
                serverConnection.cancel()
                clientTLS.close()
            }

            // Client → Server
            group.addTask { [weak self] in
                guard let self = self else { return }
                do {
                    while true {
                        let decryptedData = try await clientTLS.read()
                        state.appendToRequestBuffer(decryptedData)

                        if !state.hasRequest {
                            if let request = state.withRequestBuffer({ HTTPParser.parseRequest(from: $0) }) {
                                let url = "https://\(host)\(request.path)"
                                let body = state.withRequestBuffer { Self.extractRequestBody(from: $0, request: request) }
                                let capturedRequest = ProxyCapturedRequest(
                                    method: request.method, url: url,
                                    httpVersion: request.httpVersion,
                                    headers: request.headers, body: body
                                )
                                let currentFlowId = state.requestCount == 0 ? flowId : UUID()
                                let capturedFlow = ProxyCapturedFlow(id: currentFlowId, request: capturedRequest, processName: processName)
                                state.markRequestCaptured(flowId: currentFlowId)
                                xpcService?.addFlow(capturedFlow)
                                self.logger.info("MITM captured: \(request.method) \(url) from \(processName)")
                            }
                        }

                        try await Self.sendToServer(serverConnection, data: decryptedData)
                    }
                } catch {
                    self.logger.debug("Client→Server relay ended for \(host)")
                    serverConnection.cancel()
                }
            }

            // Server → Client
            group.addTask { [weak self] in
                guard let self = self else { return }
                do {
                    while true {
                        let serverData = try await Self.receiveFromServer(serverConnection)
                        guard !serverData.isEmpty else { continue }

                        state.appendToResponseBuffer(serverData)

                        if state.hasRequest && !state.hasResponse {
                            if let response = state.withResponseBuffer({ HTTPParser.parseResponse(from: $0) }) {
                                let elapsed = CFAbsoluteTimeGetCurrent() - startTime
                                let body = state.withResponseBuffer { Self.extractResponseBody(from: $0, response: response) }
                                let capturedResponse = ProxyCapturedResponse(
                                    statusCode: response.statusCode, reason: response.reason,
                                    httpVersion: response.httpVersion,
                                    headers: response.headers, body: body, duration: elapsed
                                )
                                let updateId = state.currentFlowId ?? flowId
                                state.markResponseCaptured()
                                xpcService?.updateFlow(updateId, response: capturedResponse)
                                state.resetForNextRequest()
                                self.logger.info("MITM response: \(response.statusCode) for \(host) (\(String(format: "%.0f", elapsed * 1000))ms)")
                            }
                        }

                        try await clientTLS.write(serverData)
                    }
                } catch {
                    self.logger.debug("Server→Client relay ended for \(host)")
                    clientTLS.close()
                }
            }
        }

        serverConnection.cancel()
        clientTLS.close()
        provider?.removeFlow(flowId)
    }
}
