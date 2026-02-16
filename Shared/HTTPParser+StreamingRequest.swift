//
//  HTTPParser+StreamingRequest.swift
//  Shared
//
//  Streaming HTTP request parser for incremental data.
//

import Foundation

extension HTTPParser {

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
}
