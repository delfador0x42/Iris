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
        flow.closeReadWithError(nil)
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
            if let request = state.withRequestBuffer({ RustHTTPParser.parseRequest(from: $0) }) {
              let scheme = isSecure ? "https" : "http"
              let url = "\(scheme)://\(host)\(request.path)"
              let body = state.withRequestBuffer {
                Self.extractRequestBody(from: $0, request: request)
              }
              let capturedRequest = ProxyCapturedRequest(
                method: request.method, url: url,
                httpVersion: request.httpVersion,
                headers: request.headers, body: body
              )
              // Track message boundary so resetForNextRequest preserves leftover data
              let bodySize = request.contentLength ?? 0
              state.setRequestMessageSize(request.headerEndIndex + bodySize)
              // Each request on a keep-alive connection gets its own flow ID
              let currentFlowId = state.requestCount == 0 ? flowId : UUID()
              let capturedFlow = ProxyCapturedFlow(
                id: currentFlowId, flowType: isSecure ? .https : .http,
                host: host, port: port,
                request: capturedRequest, processName: processName)
              state.markRequestCaptured(flowId: currentFlowId)
              xpcService?.addFlow(capturedFlow)
              self.logger.info("Captured: \(request.method) \(url) from \(processName)")
            }
          }

          do {
            try await Self.sendToServer(serverConnection, data: data)
          } catch {
            flow.closeReadWithError(nil)
            break
          }
        }
        serverConnection.cancel()
      }

      // Server → Client
      group.addTask { [weak self] in
        guard let self = self else { return }
        var parsedResponseHeaders: HTTPParser.ParsedResponse?
        var shouldCloseAfterWrite = false
        while true {
          do {
            let serverData = try await Self.receiveFromServer(serverConnection)
            guard !serverData.isEmpty else { continue }

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
                // Chunked: size unknown until terminal chunk — tracked in step 2
                // No framing: body ends when server closes connection — captured in catch block
              }
            }

            // Step 2: Check if response body is fully received
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
                // No Content-Length, not chunked — body ends on connection close (RFC 7230 §3.3.3)
                bodyComplete = false
              }

              if bodyComplete {
                Self.captureResponse(
                  state: state, response: response, flowId: flowId,
                  startTime: startTime, xpcService: xpcService
                )
                // Connection: close or HTTP/1.0 — don't reuse connection
                if response.shouldClose {
                  shouldCloseAfterWrite = true
                } else {
                  state.resetForNextRequest()
                  parsedResponseHeaders = nil
                }
              }
            }

            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
              flow.write(serverData) { _ in continuation.resume() }
            }
            if shouldCloseAfterWrite { break }
          } catch {
            // Connection closed — capture unframed response body if pending
            if let response = parsedResponseHeaders, state.hasRequest, !state.hasResponse {
              Self.captureResponse(
                state: state, response: response, flowId: flowId,
                startTime: startTime, xpcService: xpcService
              )
            }
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
