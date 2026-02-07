//
//  HTTPParserTestHelper.swift
//  IrisProxyTests
//
//  Shared test HTTP parser used by request and response parsing tests.
//

import Foundation

// MARK: - Test HTTP Parser (Standalone for Testing)
// This is a simplified version of HTTPParser for testing purposes
// since the actual HTTPParser is in the extension target

enum TestHTTPParser {

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

    static func parseRequest(from data: Data) -> ParsedRequest? {
        guard let string = String(data: data, encoding: .utf8) else {
            return nil
        }

        guard let headerEndRange = string.range(of: "\r\n\r\n") else {
            return nil
        }

        let headerString = String(string[..<headerEndRange.lowerBound])
        let headerEndIndex = data.distance(
            from: data.startIndex,
            to: data.index(
                data.startIndex,
                offsetBy: string.distance(from: string.startIndex, to: headerEndRange.upperBound)
            )
        )

        let lines = headerString.components(separatedBy: "\r\n")
        guard !lines.isEmpty else {
            return nil
        }

        let requestLine = lines[0]
        let requestParts = requestLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard requestParts.count >= 2 else {
            return nil
        }

        let method = String(requestParts[0])
        let path = String(requestParts[1])
        let httpVersion = requestParts.count > 2 ? String(requestParts[2]) : "HTTP/1.1"

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

    static func parseResponse(from data: Data) -> ParsedResponse? {
        guard let string = String(data: data, encoding: .utf8) else {
            return nil
        }

        guard let headerEndRange = string.range(of: "\r\n\r\n") else {
            return nil
        }

        let headerString = String(string[..<headerEndRange.lowerBound])
        let headerEndIndex = data.distance(
            from: data.startIndex,
            to: data.index(
                data.startIndex,
                offsetBy: string.distance(from: string.startIndex, to: headerEndRange.upperBound)
            )
        )

        let lines = headerString.components(separatedBy: "\r\n")
        guard !lines.isEmpty else {
            return nil
        }

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

    static func isConnectRequest(_ data: Data) -> Bool {
        guard data.count >= 7 else { return false }
        let prefix = String(data: data.prefix(7), encoding: .utf8)
        return prefix == "CONNECT"
    }
}
