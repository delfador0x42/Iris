import Foundation

/// A captured HTTP request.
public struct ProxyCapturedRequest: Codable, Sendable, Equatable, Hashable {
  public let method: String
  public let url: String
  public let httpVersion: String
  public let headers: [[String]]
  public let bodySize: Int
  public let bodyPreview: String?

  public init(
    method: String,
    url: String,
    httpVersion: String = "HTTP/1.1",
    headers: [[String]],
    bodySize: Int,
    bodyPreview: String? = nil
  ) {
    self.method = method
    self.url = url
    self.httpVersion = httpVersion
    self.headers = headers
    self.bodySize = bodySize
    self.bodyPreview = bodyPreview
  }

  /// Convenience init that converts tuple headers and extracts body preview.
  public init(
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
    if let body = body, !body.isEmpty {
      let previewSize = min(body.count, 1024)
      self.bodyPreview = String(data: body.prefix(previewSize), encoding: .utf8)
    } else {
      self.bodyPreview = nil
    }
  }

  public var host: String? {
    if let url = URL(string: url) { return url.host }
    return headers.first { $0.first?.lowercased() == "host" }?.last
  }

  public var path: String {
    URL(string: url)?.path ?? url
  }
}
