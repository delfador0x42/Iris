//
//  HTTPParserTests.swift
//  IrisProxyTests
//
//  Tests for HTTP parsing functionality.
//

import Testing
import Foundation

// MARK: - Test HTTP Parser (Standalone for Testing)
// This is a simplified version of HTTPParser for testing purposes
// since the actual HTTPParser is in the extension target

private enum TestHTTPParser {

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

// MARK: - Request Parsing Tests

@Suite("HTTP Request Parsing Tests")
struct HTTPRequestParsingTests {

    @Test("Parse simple GET request")
    func testParseSimpleGetRequest() {
        let request = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
        let data = Data(request.utf8)

        let parsed = TestHTTPParser.parseRequest(from: data)

        #expect(parsed != nil)
        #expect(parsed?.method == "GET")
        #expect(parsed?.path == "/path")
        #expect(parsed?.httpVersion == "HTTP/1.1")
        #expect(parsed?.host == "example.com")
    }

    @Test("Parse POST request with Content-Length")
    func testParsePostRequestWithContentLength() {
        let request = "POST /api/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 23\r\n\r\n{\"name\": \"test user\"}"
        let data = Data(request.utf8)

        let parsed = TestHTTPParser.parseRequest(from: data)

        #expect(parsed != nil)
        #expect(parsed?.method == "POST")
        #expect(parsed?.path == "/api/users")
        #expect(parsed?.contentLength == 23)
        #expect(parsed?.isChunked == false)
    }

    @Test("Parse request with chunked transfer encoding")
    func testParseChunkedRequest() {
        let request = "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
        let data = Data(request.utf8)

        let parsed = TestHTTPParser.parseRequest(from: data)

        #expect(parsed != nil)
        #expect(parsed?.isChunked == true)
        #expect(parsed?.contentLength == nil)
    }

    @Test("Parse CONNECT request")
    func testParseConnectRequest() {
        let request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        let data = Data(request.utf8)

        #expect(TestHTTPParser.isConnectRequest(data) == true)

        let parsed = TestHTTPParser.parseRequest(from: data)
        #expect(parsed?.method == "CONNECT")
        #expect(parsed?.path == "example.com:443")
    }

    @Test("Non-CONNECT request returns false for isConnectRequest")
    func testNonConnectRequest() {
        let request = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
        let data = Data(request.utf8)

        #expect(TestHTTPParser.isConnectRequest(data) == false)
    }

    @Test("Incomplete request returns nil")
    func testIncompleteRequest() {
        let request = "GET /path HTTP/1.1\r\nHost: example.com\r\n"
        let data = Data(request.utf8)

        let parsed = TestHTTPParser.parseRequest(from: data)
        #expect(parsed == nil)
    }

    @Test("Parse request with multiple headers")
    func testParseRequestMultipleHeaders() {
        let request = """
        GET /api/data HTTP/1.1\r
        Host: api.example.com\r
        User-Agent: TestClient/1.0\r
        Accept: application/json\r
        Authorization: Bearer token123\r
        Cache-Control: no-cache\r
        \r

        """
        let data = Data(request.utf8)

        let parsed = TestHTTPParser.parseRequest(from: data)

        #expect(parsed != nil)
        #expect(parsed?.headers.count == 5)

        let headerNames = parsed?.headers.map { $0.name } ?? []
        #expect(headerNames.contains("Host"))
        #expect(headerNames.contains("User-Agent"))
        #expect(headerNames.contains("Accept"))
        #expect(headerNames.contains("Authorization"))
        #expect(headerNames.contains("Cache-Control"))
    }

    @Test("Parse request with query parameters")
    func testParseRequestWithQueryParams() {
        let request = "GET /search?q=test&page=1&limit=10 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        let data = Data(request.utf8)

        let parsed = TestHTTPParser.parseRequest(from: data)

        #expect(parsed != nil)
        #expect(parsed?.path == "/search?q=test&page=1&limit=10")
    }
}

// MARK: - Response Parsing Tests

@Suite("HTTP Response Parsing Tests")
struct HTTPResponseParsingTests {

    @Test("Parse simple 200 OK response")
    func testParse200Response() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!"
        let data = Data(response.utf8)

        let parsed = TestHTTPParser.parseResponse(from: data)

        #expect(parsed != nil)
        #expect(parsed?.statusCode == 200)
        #expect(parsed?.reason == "OK")
        #expect(parsed?.httpVersion == "HTTP/1.1")
        #expect(parsed?.contentLength == 13)
    }

    @Test("Parse 404 Not Found response")
    func testParse404Response() {
        let response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n"
        let data = Data(response.utf8)

        let parsed = TestHTTPParser.parseResponse(from: data)

        #expect(parsed != nil)
        #expect(parsed?.statusCode == 404)
        #expect(parsed?.reason == "Not Found")
    }

    @Test("Parse 301 redirect response")
    func testParse301Redirect() {
        let response = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://new.example.com/\r\n\r\n"
        let data = Data(response.utf8)

        let parsed = TestHTTPParser.parseResponse(from: data)

        #expect(parsed != nil)
        #expect(parsed?.statusCode == 301)
        #expect(parsed?.reason == "Moved Permanently")

        let location = parsed?.headers.first { $0.name == "Location" }?.value
        #expect(location == "https://new.example.com/")
    }

    @Test("Parse 500 error response")
    func testParse500Error() {
        let response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n"
        let data = Data(response.utf8)

        let parsed = TestHTTPParser.parseResponse(from: data)

        #expect(parsed != nil)
        #expect(parsed?.statusCode == 500)
        #expect(parsed?.reason == "Internal Server Error")
    }

    @Test("Parse chunked response")
    func testParseChunkedResponse() {
        let response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        let data = Data(response.utf8)

        let parsed = TestHTTPParser.parseResponse(from: data)

        #expect(parsed != nil)
        #expect(parsed?.isChunked == true)
        #expect(parsed?.contentLength == nil)
    }

    @Test("Parse response with no reason phrase")
    func testParseResponseNoReason() {
        let response = "HTTP/1.1 204\r\n\r\n"
        let data = Data(response.utf8)

        let parsed = TestHTTPParser.parseResponse(from: data)

        #expect(parsed != nil)
        #expect(parsed?.statusCode == 204)
        #expect(parsed?.reason == "")
    }

    @Test("Incomplete response returns nil")
    func testIncompleteResponse() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        let data = Data(response.utf8)

        let parsed = TestHTTPParser.parseResponse(from: data)
        #expect(parsed == nil)
    }

    @Test("Parse response with multiple Set-Cookie headers")
    func testParseResponseMultipleCookies() {
        let response = """
        HTTP/1.1 200 OK\r
        Set-Cookie: session=abc123; Path=/\r
        Set-Cookie: user=john; Path=/; HttpOnly\r
        Content-Type: text/html\r
        \r

        """
        let data = Data(response.utf8)

        let parsed = TestHTTPParser.parseResponse(from: data)

        #expect(parsed != nil)
        let cookieHeaders = parsed?.headers.filter { $0.name == "Set-Cookie" }
        #expect(cookieHeaders?.count == 2)
    }
}

// MARK: - HTTP Headers Tests

@Suite("HTTP Headers Tests")
struct HTTPHeadersTests {

    @Test("HTTPHeaders case-insensitive lookup")
    func testHeadersCaseInsensitive() {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: "application/json")
        headers.add(name: "Accept", value: "text/html")

        // Case-insensitive lookup
        #expect(headers["content-type"] == "application/json")
        #expect(headers["CONTENT-TYPE"] == "application/json")
        #expect(headers["Content-Type"] == "application/json")
    }

    @Test("HTTPHeaders getAll returns multiple values")
    func testHeadersGetAll() {
        var headers = HTTPHeaders()
        headers.add(name: "Set-Cookie", value: "a=1")
        headers.add(name: "Set-Cookie", value: "b=2")
        headers.add(name: "Set-Cookie", value: "c=3")

        let cookies = headers.getAll("Set-Cookie")
        #expect(cookies.count == 3)
        #expect(cookies.contains("a=1"))
        #expect(cookies.contains("b=2"))
        #expect(cookies.contains("c=3"))
    }

    @Test("HTTPHeaders remove")
    func testHeadersRemove() {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: "application/json")
        headers.add(name: "Accept", value: "text/html")

        headers.remove(name: "Content-Type")

        #expect(headers["Content-Type"] == nil)
        #expect(headers["Accept"] == "text/html")
    }

    @Test("HTTPHeaders count")
    func testHeadersCount() {
        var headers = HTTPHeaders()
        #expect(headers.count == 0)

        headers.add(name: "A", value: "1")
        headers.add(name: "B", value: "2")
        headers.add(name: "C", value: "3")

        #expect(headers.count == 3)
    }

    @Test("HTTPHeaders iteration")
    func testHeadersIteration() {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: "text/plain")
        headers.add(name: "Content-Length", value: "100")

        var names: [String] = []
        for field in headers.fields {
            names.append(field.name)
        }

        #expect(names.count == 2)
        #expect(names.contains("Content-Type"))
        #expect(names.contains("Content-Length"))
    }
}

// MARK: - Captured Flow Tests

@Suite("ProxyCapturedFlow Tests")
struct ProxyCapturedFlowTests {

    @Test("Flow is complete when has response")
    func testFlowCompleteWithResponse() {
        let request = ProxyCapturedRequest(
            method: "GET",
            url: "https://example.com/",
            headers: [["Host", "example.com"]],
            bodySize: 0
        )

        let response = ProxyCapturedResponse(
            statusCode: 200,
            reason: "OK",
            headers: [["Content-Type", "text/html"]],
            bodySize: 100,
            duration: 0.5
        )

        let flow = ProxyCapturedFlow(
            request: request,
            response: response
        )

        #expect(flow.isComplete == true)
        #expect(flow.duration == 0.5)
    }

    @Test("Flow is complete when has error")
    func testFlowCompleteWithError() {
        let request = ProxyCapturedRequest(
            method: "GET",
            url: "https://example.com/",
            headers: [["Host", "example.com"]],
            bodySize: 0
        )

        let flow = ProxyCapturedFlow(
            request: request,
            error: "Connection refused"
        )

        #expect(flow.isComplete == true)
        #expect(flow.error == "Connection refused")
        #expect(flow.duration == nil)
    }

    @Test("Flow is not complete when pending")
    func testFlowPending() {
        let request = ProxyCapturedRequest(
            method: "GET",
            url: "https://example.com/",
            headers: [["Host", "example.com"]],
            bodySize: 0
        )

        let flow = ProxyCapturedFlow(request: request)

        #expect(flow.isComplete == false)
        #expect(flow.response == nil)
        #expect(flow.error == nil)
    }

    @Test("Request host extraction from URL")
    func testRequestHostExtraction() {
        let request = ProxyCapturedRequest(
            method: "GET",
            url: "https://api.example.com/v1/users",
            headers: [],
            bodySize: 0
        )

        #expect(request.host == "api.example.com")
    }

    @Test("Request host extraction from headers")
    func testRequestHostFromHeaders() {
        let request = ProxyCapturedRequest(
            method: "GET",
            url: "/path", // relative URL
            headers: [["Host", "example.com"]],
            bodySize: 0
        )

        #expect(request.host == "example.com")
    }

    @Test("Request path extraction")
    func testRequestPathExtraction() {
        let request = ProxyCapturedRequest(
            method: "GET",
            url: "https://example.com/api/v1/users?page=1",
            headers: [],
            bodySize: 0
        )

        #expect(request.path == "/api/v1/users")
    }

    @Test("Response success status")
    func testResponseSuccessStatus() {
        let response200 = ProxyCapturedResponse(
            statusCode: 200,
            reason: "OK",
            headers: [],
            bodySize: 0,
            duration: 0.1
        )

        let response201 = ProxyCapturedResponse(
            statusCode: 201,
            reason: "Created",
            headers: [],
            bodySize: 0,
            duration: 0.1
        )

        let response404 = ProxyCapturedResponse(
            statusCode: 404,
            reason: "Not Found",
            headers: [],
            bodySize: 0,
            duration: 0.1
        )

        #expect(response200.isSuccess == true)
        #expect(response201.isSuccess == true)
        #expect(response404.isSuccess == false)
    }

    @Test("Response error status")
    func testResponseErrorStatus() {
        let response400 = ProxyCapturedResponse(
            statusCode: 400,
            reason: "Bad Request",
            headers: [],
            bodySize: 0,
            duration: 0.1
        )

        let response500 = ProxyCapturedResponse(
            statusCode: 500,
            reason: "Internal Server Error",
            headers: [],
            bodySize: 0,
            duration: 0.1
        )

        let response200 = ProxyCapturedResponse(
            statusCode: 200,
            reason: "OK",
            headers: [],
            bodySize: 0,
            duration: 0.1
        )

        #expect(response400.isError == true)
        #expect(response500.isError == true)
        #expect(response200.isError == false)
    }

    @Test("Response content type extraction")
    func testResponseContentType() {
        let response = ProxyCapturedResponse(
            statusCode: 200,
            reason: "OK",
            headers: [["Content-Type", "application/json; charset=utf-8"]],
            bodySize: 100,
            duration: 0.1
        )

        #expect(response.contentType == "application/json; charset=utf-8")
    }

    @Test("Flow Codable conformance")
    func testFlowCodable() throws {
        let request = ProxyCapturedRequest(
            method: "POST",
            url: "https://api.example.com/users",
            headers: [["Content-Type", "application/json"]],
            bodySize: 50,
            bodyPreview: "{\"name\": \"test\"}"
        )

        let response = ProxyCapturedResponse(
            statusCode: 201,
            reason: "Created",
            headers: [["Location", "/users/123"]],
            bodySize: 20,
            duration: 0.25
        )

        let flow = ProxyCapturedFlow(
            request: request,
            response: response,
            processName: "TestApp",
            processId: 12345
        )

        // Encode
        let encoder = JSONEncoder()
        let data = try encoder.encode(flow)

        // Decode
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(ProxyCapturedFlow.self, from: data)

        #expect(decoded.id == flow.id)
        #expect(decoded.request.method == "POST")
        #expect(decoded.response?.statusCode == 201)
        #expect(decoded.processName == "TestApp")
        #expect(decoded.processId == 12345)
    }
}
