//
//  HTTPParserResponseTests.swift
//  IrisProxyTests
//
//  Tests for HTTP response parsing functionality.
//

import Testing
import Foundation

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
