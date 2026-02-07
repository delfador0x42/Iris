//
//  HTTPParser.swift
//  Shared
//
//  HTTP/1.1 request and response parser.
//  Core type definition with nested types.
//

import Foundation
import os.log

/// Parser for HTTP/1.1 requests and responses.
/// Handles streaming data and detects when headers are complete.
final class HTTPParser: @unchecked Sendable {

    let logger = Logger(subsystem: "com.wudan.iris", category: "HTTPParser")

    // MARK: - Parser State

    enum ParseState {
        case waitingForHeaders
        case parsingHeaders
        case waitingForBody
        case parsingBody
        case complete
        case error(String)
    }

    // MARK: - Parsed Result

    struct ParsedRequest {
        let method: String
        let path: String
        let httpVersion: String
        let headers: [(name: String, value: String)]
        let headerEndIndex: Int
        let contentLength: Int?
        let isChunked: Bool

        var host: String? {
            headers.first { $0.name.lowercased() == "host" }?.value
        }
    }

    struct ParsedResponse {
        let statusCode: Int
        let reason: String
        let httpVersion: String
        let headers: [(name: String, value: String)]
        let headerEndIndex: Int
        let contentLength: Int?
        let isChunked: Bool
    }
}
