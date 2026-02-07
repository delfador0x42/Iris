import Foundation
import NetworkExtension
import os.log

// MARK: - HTTP Parsing

extension FilterDataProvider {

    func parseHTTPRequest(flow: NEFilterFlow, data: Data) {
        // Check if this looks like HTTP (common HTTP methods)
        guard data.count >= 4 else { return }

        let methodPrefixes = ["GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI", "CONN"]
        guard let prefix = String(data: data.prefix(4), encoding: .utf8),
              methodPrefixes.contains(where: { prefix.hasPrefix($0.prefix(4)) }) else {
            return
        }

        // Try to parse the HTTP request
        if let parsed = HTTPParser.parseRequest(from: data) {
            // Build raw headers string
            var rawHeaders = "\(parsed.method) \(parsed.path) \(parsed.httpVersion)\r\n"
            for header in parsed.headers {
                rawHeaders += "\(header.name): \(header.value)\r\n"
            }

            let httpRequest = ParsedHTTPRequest(
                method: parsed.method,
                path: parsed.path,
                host: parsed.host,
                contentType: parsed.headers.first { $0.name.lowercased() == "content-type" }?.value,
                userAgent: parsed.headers.first { $0.name.lowercased() == "user-agent" }?.value,
                rawHeaders: rawHeaders
            )

            connectionsLock.lock()
            if let connectionId = flowToConnection[ObjectIdentifier(flow)],
               var tracker = connections[connectionId] {
                tracker.httpRequest = httpRequest
                tracker.isHTTPParsed = true
                connections[connectionId] = tracker
                logger.debug("Parsed HTTP request: \(parsed.method) \(parsed.path)")
            }
            connectionsLock.unlock()
        }
    }

    func parseHTTPResponse(flow: NEFilterFlow, data: Data) {
        // Check if this looks like HTTP response
        guard data.count >= 8 else { return }
        guard let prefix = String(data: data.prefix(8), encoding: .utf8),
              prefix.hasPrefix("HTTP/") else {
            return
        }

        // Try to parse the HTTP response
        if let parsed = HTTPParser.parseResponse(from: data) {
            // Build raw headers string
            var rawHeaders = "\(parsed.httpVersion) \(parsed.statusCode) \(parsed.reason)\r\n"
            for header in parsed.headers {
                rawHeaders += "\(header.name): \(header.value)\r\n"
            }

            let httpResponse = ParsedHTTPResponse(
                statusCode: parsed.statusCode,
                reason: parsed.reason,
                contentType: parsed.headers.first { $0.name.lowercased() == "content-type" }?.value,
                contentLength: parsed.contentLength,
                rawHeaders: rawHeaders
            )

            connectionsLock.lock()
            if let connectionId = flowToConnection[ObjectIdentifier(flow)],
               var tracker = connections[connectionId] {
                tracker.httpResponse = httpResponse
                connections[connectionId] = tracker
                logger.debug("Parsed HTTP response: \(parsed.statusCode) \(parsed.reason)")
            }
            connectionsLock.unlock()
        }
    }
}
