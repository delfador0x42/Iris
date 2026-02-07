//
//  HTTPParser+Streaming.swift
//  IrisProxyExtension
//
//  Streaming HTTP parsers for incremental request and response data.
//  Handles Content-Length and chunked Transfer-Encoding (RFC 7230 4.1).
//

import Foundation

extension HTTPParser {

    /// Maximum buffer size before we stop accumulating (16MB)
    static let maxBufferSize = 16 * 1024 * 1024

    // MARK: - Streaming Request Parser

    class StreamingRequestParser {
        var buffer = Data()
        var state: ParseState = .waitingForHeaders
        var parsedRequest: ParsedRequest?
        var bodyBytesReceived = 0

        func feed(_ data: Data) -> ParsedRequest? {
            guard buffer.count + data.count <= HTTPParser.maxBufferSize else {
                state = .error("Buffer exceeded 16MB limit")
                return parsedRequest
            }
            buffer.append(data)

            switch state {
            case .waitingForHeaders, .parsingHeaders:
                if let request = HTTPParser.parseRequest(from: buffer) {
                    parsedRequest = request
                    state = .waitingForBody

                    if let contentLength = request.contentLength, contentLength > 0 {
                        let bodyData = buffer.dropFirst(request.headerEndIndex)
                        bodyBytesReceived = bodyData.count
                        if bodyBytesReceived >= contentLength {
                            state = .complete
                            return request
                        }
                    } else if request.isChunked {
                        state = .parsingBody
                        if isChunkedComplete(from: request.headerEndIndex) {
                            state = .complete
                            return request
                        }
                    } else {
                        state = .complete
                        return request
                    }
                }

            case .waitingForBody, .parsingBody:
                if let request = parsedRequest {
                    if let contentLength = request.contentLength {
                        let bodyData = buffer.dropFirst(request.headerEndIndex)
                        bodyBytesReceived = bodyData.count
                        if bodyBytesReceived >= contentLength {
                            state = .complete
                            return request
                        }
                    } else if request.isChunked {
                        if isChunkedComplete(from: request.headerEndIndex) {
                            state = .complete
                            return request
                        }
                    }
                }

            case .complete, .error:
                break
            }

            return nil
        }

        func getBody() -> Data? {
            guard let request = parsedRequest else { return nil }
            let bodyStart = buffer.index(buffer.startIndex, offsetBy: request.headerEndIndex)
            guard bodyStart < buffer.endIndex else { return nil }
            let bodyData = Data(buffer[bodyStart...])
            return request.isChunked ? HTTPParser.decodeChunkedBody(bodyData) : bodyData
        }

        func reset() {
            buffer = Data()
            state = .waitingForHeaders
            parsedRequest = nil
            bodyBytesReceived = 0
        }

        private func isChunkedComplete(from offset: Int) -> Bool {
            HTTPParser.isChunkedBodyComplete(Data(buffer.dropFirst(offset)))
        }
    }

    // MARK: - Streaming Response Parser

    class StreamingResponseParser {
        var buffer = Data()
        var state: ParseState = .waitingForHeaders
        var parsedResponse: ParsedResponse?
        var bodyBytesReceived = 0

        func feed(_ data: Data) -> ParsedResponse? {
            guard buffer.count + data.count <= HTTPParser.maxBufferSize else {
                state = .error("Buffer exceeded 16MB limit")
                return parsedResponse
            }
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
                        if isChunkedComplete(from: response.headerEndIndex) {
                            state = .complete
                            return response
                        }
                    } else {
                        state = .complete
                        return response
                    }
                }

            case .waitingForBody, .parsingBody:
                if let response = parsedResponse {
                    if let contentLength = response.contentLength {
                        let bodyData = buffer.dropFirst(response.headerEndIndex)
                        bodyBytesReceived = bodyData.count
                        if bodyBytesReceived >= contentLength {
                            state = .complete
                            return response
                        }
                    } else if response.isChunked {
                        if isChunkedComplete(from: response.headerEndIndex) {
                            state = .complete
                            return response
                        }
                    }
                }

            case .complete, .error:
                break
            }

            return nil
        }

        func getBody() -> Data? {
            guard let response = parsedResponse else { return nil }
            let bodyStart = buffer.index(buffer.startIndex, offsetBy: response.headerEndIndex)
            guard bodyStart < buffer.endIndex else { return nil }
            let bodyData = Data(buffer[bodyStart...])
            return response.isChunked ? HTTPParser.decodeChunkedBody(bodyData) : bodyData
        }

        func reset() {
            buffer = Data()
            state = .waitingForHeaders
            parsedResponse = nil
            bodyBytesReceived = 0
        }

        private func isChunkedComplete(from offset: Int) -> Bool {
            HTTPParser.isChunkedBodyComplete(Data(buffer.dropFirst(offset)))
        }
    }

    // MARK: - Chunked Encoding Helpers

    /// Checks if chunked body ends with the final 0-length chunk.
    /// RFC 7230 4.1: last-chunk = 1*"0" CRLF CRLF
    static func isChunkedBodyComplete(_ data: Data) -> Bool {
        guard data.count >= 5 else { return false }
        // Look for "0\r\n\r\n" near the tail
        let tail = data.suffix(min(data.count, 64))
        if let str = String(data: tail, encoding: .ascii) {
            return str.contains("0\r\n\r\n")
        }
        return false
    }

    /// Decodes chunked transfer encoding into contiguous body data.
    static func decodeChunkedBody(_ data: Data) -> Data? {
        var result = Data()
        var offset = 0

        while offset < data.count {
            guard let crlfPos = findCRLF(in: data, from: offset) else { break }
            let sizeSlice = data[offset..<crlfPos]
            guard let sizeStr = String(data: sizeSlice, encoding: .ascii) else { break }
            // Chunk size is hex, may have extensions after semicolon
            let hexStr = sizeStr.split(separator: ";").first.map(String.init) ?? sizeStr
            guard let chunkSize = UInt(hexStr.trimmingCharacters(in: .whitespaces), radix: 16) else { break }

            if chunkSize == 0 { break }

            let chunkStart = crlfPos + 2
            let chunkEnd = chunkStart + Int(chunkSize)
            guard chunkEnd <= data.count else { break }

            result.append(data[chunkStart..<chunkEnd])
            offset = chunkEnd + 2 // skip trailing \r\n after chunk data
        }

        return result
    }

    private static func findCRLF(in data: Data, from offset: Int) -> Int? {
        for i in offset..<(data.count - 1) {
            if data[i] == 0x0D && data[i + 1] == 0x0A {
                return i
            }
        }
        return nil
    }
}
