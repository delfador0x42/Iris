//
//  HTTPParser+Streaming.swift
//  IrisProxyExtension
//
//  Streaming HTTP parsers for incremental request and response data.
//

import Foundation

extension HTTPParser {

    // MARK: - Streaming Request Parser

    /// Streaming HTTP parser for incremental data.
    class StreamingRequestParser {
        var buffer = Data()
        var state: ParseState = .waitingForHeaders
        var parsedRequest: ParsedRequest?
        var bodyBytesReceived = 0

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

    // MARK: - Streaming Response Parser

    /// Streaming HTTP response parser.
    class StreamingResponseParser {
        var buffer = Data()
        var state: ParseState = .waitingForHeaders
        var parsedResponse: ParsedResponse?
        var bodyBytesReceived = 0

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
}
