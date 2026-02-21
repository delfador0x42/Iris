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
    let bytesOut = ByteCounter()
    let bytesIn = ByteCounter()

    await withTaskGroup(of: Void.self) { group in
      // Overall relay timeout guard
      group.addTask {
        try? await Task.sleep(nanoseconds: UInt64(Self.maxRelayDuration * 1_000_000_000))
        serverConnection.cancel()
        clientTLS.close()
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
      }

      // Client → Server
      group.addTask { [weak self] in
        guard let self = self else { return }
        do {
          while true {
            let decryptedData = try await clientTLS.read()
            bytesOut.add(Int64(decryptedData.count))
            state.appendToRequestBuffer(decryptedData)

            if !state.hasRequest {
              if let request = state.withRequestBuffer({ RustHTTPParser.parseRequest(from: $0) }) {
                let url = "https://\(host)\(request.path)"
                let body = state.withRequestBuffer {
                  Self.extractRequestBody(from: $0, request: request)
                }
                let capturedRequest = ProxyCapturedRequest(
                  method: request.method, url: url,
                  httpVersion: request.httpVersion,
                  headers: request.headers, body: body
                )
                // Track message boundary so resetForNextRequest preserves leftover data
                let isChunked = request.isChunked
                let bodySize = request.contentLength ?? 0
                if !isChunked {
                  state.setRequestMessageSize(request.headerEndIndex + bodySize)
                }
                // Store parse info for chunked body tracking
                state.setRequestParseInfo(headerEndIndex: request.headerEndIndex, isChunked: isChunked)
                let currentFlowId = state.requestCount == 0 ? flowId : UUID()
                let capturedFlow = ProxyCapturedFlow(
                  id: currentFlowId, flowType: .https, host: host, port: port,
                  request: capturedRequest, processName: processName)
                state.markRequestCaptured(flowId: currentFlowId)
                xpcService?.addFlow(capturedFlow)
                self.logger.info("MITM captured: \(request.method) \(url) from \(processName)")
              }
            }

            // For chunked requests, detect terminal chunk to set correct message boundary
            if state.hasRequest && state.requestIsChunked {
              if state.isChunkedRequestBodyComplete() {
                let actualSize = state.withRequestBuffer { $0.count }
                state.setRequestMessageSize(actualSize)
              }
            }

            try await Self.sendToServer(serverConnection, data: decryptedData)
          }
        } catch {
          self.logger.debug("Client→Server relay ended for \(host)")
          clientTLS.close()
          serverConnection.cancel()
        }
      }

      // Server → Client
      group.addTask { [weak self] in
        guard let self = self else { return }
        var parsedResponseHeaders: HTTPParser.ParsedResponse?
        var shouldCloseAfterWrite = false
        do {
          while true {
            let serverData = try await Self.receiveFromServer(serverConnection)
            guard !serverData.isEmpty else { continue }
            bytesIn.add(Int64(serverData.count))

            state.appendToResponseBuffer(serverData)

            // Step 1: Parse response headers (once per request/response cycle)
            if state.hasRequest && !state.hasResponse && parsedResponseHeaders == nil {
              parsedResponseHeaders = state.withResponseBuffer({
                RustHTTPParser.parseResponse(from: $0)
              })
              if let response = parsedResponseHeaders {
                if !response.hasBody {
                  state.setResponseMessageSize(response.headerEndIndex)
                  state.markResponseBodyComplete(actualSize: response.headerEndIndex)
                } else if let contentLength = response.contentLength {
                  state.setResponseMessageSize(response.headerEndIndex + contentLength)
                }
              }
            }

            // Step 2: Check if response body is fully received before resetting
            if let response = parsedResponseHeaders, !state.hasResponse {
              let bodyComplete: Bool
              if response.isChunked {
                bodyComplete = state.withResponseBuffer { buf in
                  let bodyData = Data(buf.dropFirst(response.headerEndIndex))
                  return HTTPParser.isChunkedBodyComplete(bodyData)
                }
                if bodyComplete {
                  let actualSize = state.withResponseBuffer({ $0.count })
                  state.markResponseBodyComplete(actualSize: actualSize)
                }
              } else if response.hasFraming {
                bodyComplete = state.isResponseComplete()
              } else {
                bodyComplete = false
              }

              if bodyComplete {
                Self.captureResponse(
                  state: state, response: response, flowId: flowId,
                  startTime: startTime, xpcService: xpcService
                )
                self.logger.info(
                  "MITM response: \(response.statusCode) for \(host) (\(String(format: "%.0f", (CFAbsoluteTimeGetCurrent() - startTime) * 1000))ms)"
                )
                if response.shouldClose {
                  shouldCloseAfterWrite = true
                } else {
                  state.resetForNextRequest()
                  parsedResponseHeaders = nil
                  // Re-parse leftover buffer for pipelined requests
                  Self.capturePipelinedRequest(
                    state: state, host: host, port: port,
                    processName: processName, isSecure: true,
                    xpcService: xpcService
                  )
                }
              }
            }

            try await clientTLS.write(serverData)
            if shouldCloseAfterWrite { break }
          }
        } catch {
          // Connection closed — capture unframed response body if pending
          if let response = parsedResponseHeaders, state.hasRequest, !state.hasResponse {
            Self.captureResponse(
              state: state, response: response, flowId: flowId,
              startTime: startTime, xpcService: xpcService
            )
          }
          self.logger.debug("Server→Client relay ended for \(host)")
          clientTLS.close()
        }
      }
    }

    serverConnection.cancel()
    clientTLS.close()
    xpcService?.completeFlow(
      flowId, bytesIn: bytesIn.value, bytesOut: bytesOut.value, error: nil)
    provider?.removeFlow(flowId)
  }
}
