//
//  HTTPParser+Utilities.swift
//  IrisNetworkExtension
//
//  CONNECT request detection and HTTP message building utilities.
//

import Foundation

extension HTTPParser {

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
