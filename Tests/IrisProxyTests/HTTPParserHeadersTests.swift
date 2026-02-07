//
//  HTTPParserHeadersTests.swift
//  IrisProxyTests
//
//  Tests for HTTPHeaders functionality.
//

import Testing
import Foundation

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
