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
}
