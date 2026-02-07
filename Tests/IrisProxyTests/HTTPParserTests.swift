//
//  HTTPParserTests.swift
//  IrisProxyTests
//
//  Tests for ProxyCapturedFlow functionality.
//

import Testing
import Foundation

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
