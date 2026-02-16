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

        /// Whether the server indicated this connection should close after the response.
        /// True for HTTP/1.0 without explicit keep-alive, or any version with Connection: close.
        var shouldClose: Bool {
            let connHeader = headers.first { $0.name.lowercased() == "connection" }?.value.lowercased()
            if connHeader == "close" { return true }
            // HTTP/1.0 defaults to close unless Connection: keep-alive
            if httpVersion == "HTTP/1.0" && connHeader != "keep-alive" { return true }
            return false
        }

        /// Whether this response has a body (RFC 7230 §3.3)
        var hasBody: Bool {
            // 1xx, 204, 304 have no body
            if statusCode < 200 || statusCode == 204 || statusCode == 304 { return false }
            return true
        }

        /// Whether the body length is determinate (Content-Length or chunked)
        var hasFraming: Bool {
            contentLength != nil || isChunked
        }
    }
}
