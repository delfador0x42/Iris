//
//  FlowHandler+Helpers.swift
//  IrisProxyExtension
//
//  Shared helpers for NWConnection send/receive and HTTP body extraction.
//

import Foundation
import Network

extension FlowHandler {

    /// Sends data to a server NWConnection.
    static func sendToServer(_ connection: NWConnection, data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    /// Receives data from a server NWConnection with idle timeout.
    static func receiveFromServer(_ connection: NWConnection) async throws -> Data {
        try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                        if let error = error {
                            continuation.resume(throwing: error)
                            return
                        }
                        if let data = data, !data.isEmpty {
                            continuation.resume(returning: data)
                        } else if isComplete {
                            continuation.resume(throwing: TLSSessionError.connectionClosed)
                        } else {
                            continuation.resume(returning: Data())
                        }
                    }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(FlowHandler.idleTimeout * 1_000_000_000))
                throw TLSSessionError.timeout
            }
            let result = try await group.next() ?? Data()
            group.cancelAll()
            return result
        }
    }

    /// Extracts HTTP request body from buffer using parsed request info.
    static func extractRequestBody(from buffer: Data, request: HTTPParser.ParsedRequest) -> Data? {
        if let contentLength = request.contentLength, contentLength > 0,
           request.headerEndIndex < buffer.count {
            let bodyStart = buffer.index(buffer.startIndex, offsetBy: request.headerEndIndex)
            let bodyEnd = buffer.index(bodyStart, offsetBy: min(contentLength, buffer.count - request.headerEndIndex))
            return Data(buffer[bodyStart..<bodyEnd])
        }
        return nil
    }

    /// Extracts HTTP response body from buffer using parsed response info.
    static func extractResponseBody(from buffer: Data, response: HTTPParser.ParsedResponse) -> Data? {
        if let contentLength = response.contentLength, contentLength > 0,
           response.headerEndIndex < buffer.count {
            let bodyStart = buffer.index(buffer.startIndex, offsetBy: response.headerEndIndex)
            let bodyEnd = buffer.index(bodyStart, offsetBy: min(contentLength, buffer.count - response.headerEndIndex))
            return Data(buffer[bodyStart..<bodyEnd])
        }
        return nil
    }

    /// Captures a completed HTTP response to the XPC flow store.
    static func captureResponse(
        state: RelayState, response: HTTPParser.ParsedResponse,
        flowId: UUID, startTime: CFAbsoluteTime,
        xpcService: ProxyXPCService?
    ) {
        let elapsed = CFAbsoluteTimeGetCurrent() - startTime
        let body = extractResponseBody(from: state.getResponseBuffer(), response: response)
        let capturedResponse = ProxyCapturedResponse(
            statusCode: response.statusCode, reason: response.reason,
            httpVersion: response.httpVersion,
            headers: response.headers, body: body, duration: elapsed
        )
        let updateId = state.currentFlowId ?? flowId
        let actualRequestBodyBytes = Int64(state.requestBodyBytes)
        state.markResponseCaptured()
        xpcService?.updateFlow(updateId, response: capturedResponse, requestBodySize: actualRequestBodyBytes)
    }

    /// After resetForNextRequest, check if leftover buffer contains a pipelined request.
    /// The data was already sent to the server by the Client→Server task; this just
    /// ensures the capture pipeline sees the request so responses get associated.
    static func capturePipelinedRequest(
        state: RelayState, host: String, port: Int,
        processName: String, isSecure: Bool, xpcService: ProxyXPCService?
    ) {
        guard !state.hasRequest else { return }
        guard let request = state.withRequestBuffer({
            RustHTTPParser.parseRequest(from: $0)
        }) else { return }
        let scheme = isSecure ? "https" : "http"
        let url = "\(scheme)://\(host)\(request.path)"
        let body = state.withRequestBuffer {
            extractRequestBody(from: $0, request: request)
        }
        let capturedRequest = ProxyCapturedRequest(
            method: request.method, url: url, httpVersion: request.httpVersion,
            headers: request.headers, body: body
        )
        let isChunked = request.isChunked
        let bodySize = request.contentLength ?? 0
        if !isChunked {
            state.setRequestMessageSize(request.headerEndIndex + bodySize)
        }
        state.setRequestParseInfo(headerEndIndex: request.headerEndIndex, isChunked: isChunked)
        let pipelinedFlowId = UUID()
        let capturedFlow = ProxyCapturedFlow(
            id: pipelinedFlowId, flowType: isSecure ? .https : .http,
            host: host, port: port, request: capturedRequest, processName: processName
        )
        state.markRequestCaptured(flowId: pipelinedFlowId)
        xpcService?.addFlow(capturedFlow)
    }
}
