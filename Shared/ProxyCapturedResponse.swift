import Foundation

/// A captured HTTP response.
public struct ProxyCapturedResponse: Codable, Sendable, Equatable, Hashable {
  public let statusCode: Int
  public let reason: String
  public let httpVersion: String
  public let headers: [[String]]
  public let bodySize: Int
  public let bodyPreview: String?
  public let duration: TimeInterval

  public init(
    statusCode: Int,
    reason: String,
    httpVersion: String = "HTTP/1.1",
    headers: [[String]],
    bodySize: Int,
    bodyPreview: String? = nil,
    duration: TimeInterval
  ) {
    self.statusCode = statusCode
    self.reason = reason
    self.httpVersion = httpVersion
    self.headers = headers
    self.bodySize = bodySize
    self.bodyPreview = bodyPreview
    self.duration = duration
  }

  /// Convenience init that converts tuple headers and extracts body preview.
  public init(
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

  public var isSuccess: Bool { statusCode >= 200 && statusCode < 300 }
  public var isError: Bool { statusCode >= 400 }

  public var contentType: String? {
    headers.first { $0.first?.lowercased() == "content-type" }?.last
  }
}
