//
//  HTTPParser.swift
//  IrisNetworkExtension
//
//  HTTP/1.1 request and response parser for network monitoring.
//

import Foundation
import os.log

/// Parser for HTTP/1.1 requests and responses.
/// Handles streaming data and detects when headers are complete.
final class HTTPParser: @unchecked Sendable {

    private let logger = Logger(subsystem: "com.wudan.iris.network", category: "HTTPParser")

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

    // MARK: - Request Parsing

    /// Parses an HTTP request from raw data.
    /// Returns nil if the data is incomplete (headers not finished).
    static func parseRequest(from data: Data) -> ParsedRequest? {
        guard let string = String(data: data, encoding: .utf8) else {
            return nil
        }

        // Find end of headers
        guard let headerEndRange = string.range(of: "\r\n\r\n") else {
            return nil // Headers not complete
        }

        let headerString = String(string[..<headerEndRange.lowerBound])
        let headerEndIndex = data.distance(from: data.startIndex, to: data.index(data.startIndex, offsetBy: string.distance(from: string.startIndex, to: headerEndRange.upperBound)))

        let lines = headerString.components(separatedBy: "\r\n")
        guard !lines.isEmpty else {
            return nil
        }

        // Parse request line
        let requestLine = lines[0]
        let requestParts = requestLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard requestParts.count >= 2 else {
            return nil
        }

        let method = String(requestParts[0])
        let path = String(requestParts[1])
        let httpVersion = requestParts.count > 2 ? String(requestParts[2]) : "HTTP/1.1"

        // Parse headers
        var headers: [(name: String, value: String)] = []
        for i in 1..<lines.count {
            let line = lines[i]
            if line.isEmpty { break }

            if let colonIndex = line.firstIndex(of: ":") {
                let name = String(line[..<colonIndex])
                let valueStart = line.index(after: colonIndex)
                let value = String(line[valueStart...]).trimmingCharacters(in: .whitespaces)
                headers.append((name, value))
            }
        }

        // Determine content length and transfer encoding
        let contentLength = headers.first { $0.name.lowercased() == "content-length" }
            .flatMap { Int($0.value) }

        let isChunked = headers.first { $0.name.lowercased() == "transfer-encoding" }?
            .value.lowercased().contains("chunked") ?? false

        return ParsedRequest(
            method: method,
            path: path,
            httpVersion: httpVersion,
            headers: headers,
            headerEndIndex: headerEndIndex,
            contentLength: contentLength,
            isChunked: isChunked
        )
    }

    /// Parses an HTTP response from raw data.
    /// Returns nil if the data is incomplete (headers not finished).
    static func parseResponse(from data: Data) -> ParsedResponse? {
        guard let string = String(data: data, encoding: .utf8) else {
            return nil
        }

        // Find end of headers
        guard let headerEndRange = string.range(of: "\r\n\r\n") else {
            return nil // Headers not complete
        }

        let headerString = String(string[..<headerEndRange.lowerBound])
        let headerEndIndex = data.distance(from: data.startIndex, to: data.index(data.startIndex, offsetBy: string.distance(from: string.startIndex, to: headerEndRange.upperBound)))

        let lines = headerString.components(separatedBy: "\r\n")
        guard !lines.isEmpty else {
            return nil
        }

        // Parse status line
        let statusLine = lines[0]
        let statusParts = statusLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard statusParts.count >= 2 else {
            return nil
        }

        let httpVersion = String(statusParts[0])
        guard let statusCode = Int(statusParts[1]) else {
            return nil
        }
        let reason = statusParts.count > 2 ? String(statusParts[2]) : ""

        // Parse headers
        var headers: [(name: String, value: String)] = []
        for i in 1..<lines.count {
            let line = lines[i]
            if line.isEmpty { break }

            if let colonIndex = line.firstIndex(of: ":") {
                let name = String(line[..<colonIndex])
                let valueStart = line.index(after: colonIndex)
                let value = String(line[valueStart...]).trimmingCharacters(in: .whitespaces)
                headers.append((name, value))
            }
        }

        // Determine content length and transfer encoding
        let contentLength = headers.first { $0.name.lowercased() == "content-length" }
            .flatMap { Int($0.value) }

        let isChunked = headers.first { $0.name.lowercased() == "transfer-encoding" }?
            .value.lowercased().contains("chunked") ?? false

        return ParsedResponse(
            statusCode: statusCode,
            reason: reason,
            httpVersion: httpVersion,
            headers: headers,
            headerEndIndex: headerEndIndex,
            contentLength: contentLength,
            isChunked: isChunked
        )
    }

    // MARK: - Streaming Parser

    /// Streaming HTTP parser for incremental data.
    class StreamingRequestParser {
        private var buffer = Data()
        private var state: ParseState = .waitingForHeaders
        private var parsedRequest: ParsedRequest?
        private var bodyBytesReceived = 0

        /// Feeds data to the parser.
        /// Returns the parsed request when complete, or nil if more data needed.
        func feed(_ data: Data) -> ParsedRequest? {
            buffer.append(data)

            switch state {
            case .waitingForHeaders, .parsingHeaders:
                if let request = HTTPParser.parseRequest(from: buffer) {
                    parsedRequest = request
                    state = .waitingForBody

                    // Check if we have body to read
                    if let contentLength = request.contentLength, contentLength > 0 {
                        let bodyData = buffer.dropFirst(request.headerEndIndex)
                        bodyBytesReceived = bodyData.count
                        if bodyBytesReceived >= contentLength {
                            state = .complete
                            return request
                        }
                    } else if request.isChunked {
                        // TODO: Handle chunked encoding
                        state = .parsingBody
                    } else {
                        // No body expected
                        state = .complete
                        return request
                    }
                }

            case .waitingForBody, .parsingBody:
                if let request = parsedRequest, let contentLength = request.contentLength {
                    let bodyData = buffer.dropFirst(request.headerEndIndex)
                    bodyBytesReceived = bodyData.count
                    if bodyBytesReceived >= contentLength {
                        state = .complete
                        return request
                    }
                }

            case .complete, .error:
                break
            }

            return nil
        }

        /// Gets the body data if available.
        func getBody() -> Data? {
            guard let request = parsedRequest else { return nil }
            let bodyStart = buffer.index(buffer.startIndex, offsetBy: request.headerEndIndex)
            return Data(buffer[bodyStart...])
        }

        /// Resets the parser for the next request.
        func reset() {
            buffer = Data()
            state = .waitingForHeaders
            parsedRequest = nil
            bodyBytesReceived = 0
        }
    }

    /// Streaming HTTP response parser.
    class StreamingResponseParser {
        private var buffer = Data()
        private var state: ParseState = .waitingForHeaders
        private var parsedResponse: ParsedResponse?
        private var bodyBytesReceived = 0

        /// Feeds data to the parser.
        func feed(_ data: Data) -> ParsedResponse? {
            buffer.append(data)

            switch state {
            case .waitingForHeaders, .parsingHeaders:
                if let response = HTTPParser.parseResponse(from: buffer) {
                    parsedResponse = response
                    state = .waitingForBody

                    if let contentLength = response.contentLength, contentLength > 0 {
                        let bodyData = buffer.dropFirst(response.headerEndIndex)
                        bodyBytesReceived = bodyData.count
                        if bodyBytesReceived >= contentLength {
                            state = .complete
                            return response
                        }
                    } else if response.isChunked {
                        state = .parsingBody
                    } else {
                        state = .complete
                        return response
                    }
                }

            case .waitingForBody, .parsingBody:
                if let response = parsedResponse, let contentLength = response.contentLength {
                    let bodyData = buffer.dropFirst(response.headerEndIndex)
                    bodyBytesReceived = bodyData.count
                    if bodyBytesReceived >= contentLength {
                        state = .complete
                        return response
                    }
                }

            case .complete, .error:
                break
            }

            return nil
        }

        /// Gets the body data if available.
        func getBody() -> Data? {
            guard let response = parsedResponse else { return nil }
            let bodyStart = buffer.index(buffer.startIndex, offsetBy: response.headerEndIndex)
            return Data(buffer[bodyStart...])
        }

        /// Resets the parser.
        func reset() {
            buffer = Data()
            state = .waitingForHeaders
            parsedResponse = nil
            bodyBytesReceived = 0
        }
    }

    // MARK: - CONNECT Request Detection

    /// Checks if data starts with a CONNECT request (HTTPS tunneling).
    static func isConnectRequest(_ data: Data) -> Bool {
        guard data.count >= 7 else { return false }
        let prefix = String(data: data.prefix(7), encoding: .utf8)
        return prefix == "CONNECT"
    }

    /// Parses a CONNECT request to extract target host and port.
    static func parseConnectRequest(_ data: Data) -> (host: String, port: Int)? {
        guard let request = parseRequest(from: data),
              request.method == "CONNECT" else {
            return nil
        }

        // CONNECT host:port HTTP/1.1
        let target = request.path
        let parts = target.split(separator: ":")
        guard parts.count == 2,
              let port = Int(parts[1]) else {
            return nil
        }

        return (String(parts[0]), port)
    }

    // MARK: - Header Utilities

    /// Builds an HTTP request string from components.
    static func buildRequest(
        method: String,
        path: String,
        httpVersion: String = "HTTP/1.1",
        headers: [(name: String, value: String)],
        body: Data? = nil
    ) -> Data {
        var request = "\(method) \(path) \(httpVersion)\r\n"
        for header in headers {
            request += "\(header.name): \(header.value)\r\n"
        }
        request += "\r\n"

        var data = Data(request.utf8)
        if let body = body {
            data.append(body)
        }
        return data
    }

    /// Builds an HTTP response string from components.
    static func buildResponse(
        statusCode: Int,
        reason: String? = nil,
        httpVersion: String = "HTTP/1.1",
        headers: [(name: String, value: String)],
        body: Data? = nil
    ) -> Data {
        let reasonPhrase = reason ?? defaultReason(for: statusCode)
        var response = "\(httpVersion) \(statusCode) \(reasonPhrase)\r\n"
        for header in headers {
            response += "\(header.name): \(header.value)\r\n"
        }
        response += "\r\n"

        var data = Data(response.utf8)
        if let body = body {
            data.append(body)
        }
        return data
    }

    /// Gets the default reason phrase for a status code.
    static func defaultReason(for statusCode: Int) -> String {
        switch statusCode {
        case 200: return "OK"
        case 201: return "Created"
        case 204: return "No Content"
        case 301: return "Moved Permanently"
        case 302: return "Found"
        case 304: return "Not Modified"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 405: return "Method Not Allowed"
        case 500: return "Internal Server Error"
        case 502: return "Bad Gateway"
        case 503: return "Service Unavailable"
        case 504: return "Gateway Timeout"
        default: return "Unknown"
        }
    }

    /// Builds a "200 Connection Established" response for CONNECT.
    static func buildConnectResponse() -> Data {
        return Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)
    }
}
