//
//  FlowHandler+HTTPRelay.swift
//  IrisProxyExtension
//
//  Plaintext HTTP relay: relays traffic while parsing and capturing flows.
//

import Foundation
import Network
import NetworkExtension
import os.log

extension FlowHandler {

    /// Relays plaintext HTTP while parsing and capturing flows.
    func relayAndCapture(
        flowId: UUID, flow: NEAppProxyTCPFlow,
        serverConnection: NWConnection,
        host: String, port: Int,
        processName: String, isSecure: Bool
    ) async {
        let startTime = CFAbsoluteTimeGetCurrent()
        let state = RelayState()
        let xpcService = self.provider?.xpcService

        await withTaskGroup(of: Void.self) { group in
            // Overall relay timeout guard
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(Self.maxRelayDuration * 1_000_000_000))
                serverConnection.cancel()
                flow.closeWriteWithError(nil)
            }

            // Client → Server
            group.addTask { [weak self] in
                guard let self = self else { return }
                while true {
                    let result: (data: Data?, error: Error?) = await withCheckedContinuation { continuation in
                        flow.readData { data, error in
                            continuation.resume(returning: (data, error))
                        }
                    }
                    if result.error != nil { break }
                    guard let data = result.data, !data.isEmpty else { break }

                    state.appendToRequestBuffer(data)

                    if !state.hasRequest {
                        if let request = HTTPParser.parseRequest(from: state.getRequestBuffer()) {
                            let scheme = isSecure ? "https" : "http"
                            let url = "\(scheme)://\(host)\(request.path)"
                            let body = Self.extractRequestBody(from: state.getRequestBuffer(), request: request)
                            let capturedRequest = ProxyCapturedRequest(
                                method: request.method, url: url,
                                httpVersion: request.httpVersion,
                                headers: request.headers, body: body
                            )
                            let capturedFlow = ProxyCapturedFlow(id: flowId, request: capturedRequest, processName: processName)
                            state.markRequestCaptured()
                            xpcService?.addFlow(capturedFlow)
                            self.logger.info("Captured: \(request.method) \(url) from \(processName)")
                        }
                    }

                    do {
                        try await Self.sendToServer(serverConnection, data: data)
                    } catch { break }
                }
                serverConnection.cancel()
            }

            // Server → Client
            group.addTask { [weak self] in
                guard let self = self else { return }
                while true {
                    do {
                        let serverData = try await Self.receiveFromServer(serverConnection)
                        guard !serverData.isEmpty else { continue }

                        state.appendToResponseBuffer(serverData)

                        if state.hasRequest && !state.hasResponse {
                            if let response = HTTPParser.parseResponse(from: state.getResponseBuffer()) {
                                let elapsed = CFAbsoluteTimeGetCurrent() - startTime
                                let body = Self.extractResponseBody(from: state.getResponseBuffer(), response: response)
                                let capturedResponse = ProxyCapturedResponse(
                                    statusCode: response.statusCode, reason: response.reason,
                                    httpVersion: response.httpVersion,
                                    headers: response.headers, body: body, duration: elapsed
                                )
                                state.markResponseCaptured()
                                xpcService?.updateFlow(flowId, response: capturedResponse)
                            }
                        }

                        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                            flow.write(serverData) { _ in continuation.resume() }
                        }
                    } catch {
                        flow.closeWriteWithError(nil)
                        break
                    }
                }
            }
        }

        serverConnection.cancel()
        provider?.removeFlow(flowId)
    }
}
