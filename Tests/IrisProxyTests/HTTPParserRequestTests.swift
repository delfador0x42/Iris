//
//  HTTPParserRequestTests.swift
//  IrisProxyTests
//
//  Tests for HTTP request parsing functionality.
//

import Testing
import Foundation

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
