//
//  HTTPParser+StreamingResponse.swift
//  Shared
//
//  Streaming HTTP response parser for incremental data.
//

import Foundation

extension HTTPParser {

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
}
