//
//  HTTPParser+RequestParsing.swift
//  Shared
//
//  Static methods for parsing HTTP requests and responses from raw data.
//  Uses byte-level search for header boundary to avoid String/Data offset mismatch.
//

import Foundation

extension HTTPParser {

    // MARK: - Header Boundary Search

    /// Finds the byte offset of the end of HTTP headers (\r\n\r\n) in raw data.
    /// Returns the offset AFTER the \r\n\r\n sequence (start of body).
    /// Using byte-level search avoids String/Data distance mismatch on non-ASCII.
    static func findHeaderEnd(in data: Data) -> Int? {
        let cr: UInt8 = 0x0D  // \r
        let lf: UInt8 = 0x0A  // \n
        guard data.count >= 4 else { return nil }
        for i in 0..<(data.count - 3) {
            if data[i] == cr && data[i+1] == lf && data[i+2] == cr && data[i+3] == lf {
                return i + 4
            }
        }
        return nil
    }

    // MARK: - Request Parsing

    /// Parses an HTTP request from raw data.
    /// Returns nil if the data is incomplete (headers not finished).
    static func parseRequest(from data: Data) -> ParsedRequest? {
        guard let headerEndIndex = findHeaderEnd(in: data) else {
            return nil
        }

        let headerData = data[data.startIndex..<data.index(data.startIndex, offsetBy: headerEndIndex - 4)]
        guard let headerString = String(data: headerData, encoding: .utf8) else {
            return nil
        }

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

    // MARK: - Response Parsing

    /// Parses an HTTP response from raw data.
    /// Returns nil if the data is incomplete (headers not finished).
    static func parseResponse(from data: Data) -> ParsedResponse? {
        guard let headerEndIndex = findHeaderEnd(in: data) else {
            return nil
        }

        let headerData = data[data.startIndex..<data.index(data.startIndex, offsetBy: headerEndIndex - 4)]
        guard let headerString = String(data: headerData, encoding: .utf8) else {
            return nil
        }

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
}
