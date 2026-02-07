//
//  ProxyXPCService+Models.swift
//  IrisProxyExtension
//
//  Captured flow data models for the proxy extension.
//

import Foundation

// MARK: - Captured Flow Models

/// A captured HTTP flow (request + optional response).
struct CapturedFlow: Codable, Identifiable {
    let id: UUID
    let timestamp: Date
    let request: CapturedRequest
    var response: CapturedResponse?
    var error: String?
    let processName: String?
    let processId: Int?

    init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        request: CapturedRequest,
        response: CapturedResponse? = nil,
        error: String? = nil,
        processName: String? = nil,
        processId: Int? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.request = request
        self.response = response
        self.error = error
        self.processName = processName
        self.processId = processId
    }
}

/// A captured HTTP request.
struct CapturedRequest: Codable {
    let method: String
    let url: String
    let httpVersion: String
    let headers: [[String]]
    let bodySize: Int
    let bodyPreview: String?

    init(
        method: String,
        url: String,
        httpVersion: String = "HTTP/1.1",
        headers: [(name: String, value: String)],
        body: Data? = nil
    ) {
        self.method = method
        self.url = url
        self.httpVersion = httpVersion
        self.headers = headers.map { [$0.name, $0.value] }
        self.bodySize = body?.count ?? 0

        // Store preview of body (first 1KB)
        if let body = body, !body.isEmpty {
            let previewSize = min(body.count, 1024)
            self.bodyPreview = String(data: body.prefix(previewSize), encoding: .utf8)
        } else {
            self.bodyPreview = nil
        }
    }
}

/// A captured HTTP response.
struct CapturedResponse: Codable {
    let statusCode: Int
    let reason: String
    let httpVersion: String
    let headers: [[String]]
    let bodySize: Int
    let bodyPreview: String?
    let duration: TimeInterval

    init(
        statusCode: Int,
        reason: String,
        httpVersion: String = "HTTP/1.1",
        headers: [(name: String, value: String)],
        body: Data? = nil,
        duration: TimeInterval
    ) {
        self.statusCode = statusCode
        self.reason = reason
        self.httpVersion = httpVersion
        self.headers = headers.map { [$0.name, $0.value] }
        self.bodySize = body?.count ?? 0
        self.duration = duration

        if let body = body, !body.isEmpty {
            let previewSize = min(body.count, 1024)
            self.bodyPreview = String(data: body.prefix(previewSize), encoding: .utf8)
        } else {
            self.bodyPreview = nil
        }
    }
}
