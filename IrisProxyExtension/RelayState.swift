//
//  RelayState.swift
//  IrisProxyExtension
//
//  Thread-safe shared state for bidirectional relay between @Sendable TaskGroup closures.
//  Both relay directions (client→server, server→client) need to share mutable buffers
//  for HTTP parsing, but TaskGroup closures are @Sendable and can't capture `var` bindings.
//

import Foundation

/// Lock-protected reference type for shared relay state.
final class RelayState: @unchecked Sendable {
  private let lock = NSLock()
  private var _requestBuffer = Data()
  private var _responseBuffer = Data()
  private var _hasRequest = false
  private var _hasResponse = false
  private var _requestCount = 0
  private var _currentFlowId: UUID?
  private var _requestMessageSize: Int?
  private var _responseMessageSize: Int?
  /// Whether the response body is fully received (for keep-alive boundary tracking)
  private var _responseBodyComplete = false
  /// Request header end index (where body begins), set when request is parsed
  private var _requestHeaderEndIndex: Int = 0
  /// Whether the current request uses Transfer-Encoding: chunked
  private var _requestIsChunked = false

  /// Max buffer size per direction (16 MB) to prevent unbounded growth
  static let maxBufferSize = 16 * 1024 * 1024

  var hasRequest: Bool {
    lock.lock()
    defer { lock.unlock() }
    return _hasRequest
  }

  var hasResponse: Bool {
    lock.lock()
    defer { lock.unlock() }
    return _hasResponse
  }

  func appendToRequestBuffer(_ data: Data) {
    lock.lock()
    if _requestBuffer.count + data.count <= Self.maxBufferSize {
      _requestBuffer.append(data)
    }
    lock.unlock()
  }

  func appendToResponseBuffer(_ data: Data) {
    lock.lock()
    if _responseBuffer.count + data.count <= Self.maxBufferSize {
      _responseBuffer.append(data)
    }
    lock.unlock()
  }

  func getRequestBuffer() -> Data {
    lock.lock()
    defer { lock.unlock() }
    return _requestBuffer
  }

  func getResponseBuffer() -> Data {
    lock.lock()
    defer { lock.unlock() }
    return _responseBuffer
  }

  /// Access request buffer under lock without copying
  func withRequestBuffer<T>(_ body: (Data) -> T) -> T {
    lock.lock()
    defer { lock.unlock() }
    return body(_requestBuffer)
  }

  /// Access response buffer under lock without copying
  func withResponseBuffer<T>(_ body: (Data) -> T) -> T {
    lock.lock()
    defer { lock.unlock() }
    return body(_responseBuffer)
  }

  /// The flow ID for the current request/response cycle (set when request is captured)
  var currentFlowId: UUID? {
    lock.lock()
    defer { lock.unlock() }
    return _currentFlowId
  }

  /// Number of requests captured on this connection (0-indexed)
  var requestCount: Int {
    lock.lock()
    defer { lock.unlock() }
    return _requestCount
  }

  func markRequestCaptured(flowId: UUID) {
    lock.lock()
    _hasRequest = true
    _currentFlowId = flowId
    lock.unlock()
  }

  /// Store request parse metadata for chunked body tracking.
  func setRequestParseInfo(headerEndIndex: Int, isChunked: Bool) {
    lock.lock()
    _requestHeaderEndIndex = headerEndIndex
    _requestIsChunked = isChunked
    lock.unlock()
  }

  var requestIsChunked: Bool {
    lock.lock()
    defer { lock.unlock() }
    return _requestIsChunked
  }

  /// Check if the chunked request body is complete (terminal chunk detected).
  /// Uses the same HTTPParser.isChunkedBodyComplete() as the response side.
  func isChunkedRequestBodyComplete() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard _requestIsChunked, _requestHeaderEndIndex > 0 else { return false }
    let bodyStart = _requestHeaderEndIndex
    guard bodyStart < _requestBuffer.count else { return false }
    let bodyData = Data(_requestBuffer[bodyStart...])
    return HTTPParser.isChunkedBodyComplete(bodyData)
  }

  /// Actual request body bytes accumulated (buffer bytes after header end).
  var requestBodyBytes: Int {
    lock.lock()
    defer { lock.unlock() }
    return max(0, _requestBuffer.count - _requestHeaderEndIndex)
  }

  func markResponseCaptured() {
    lock.lock()
    _hasResponse = true
    lock.unlock()
  }

  /// Set the total byte size of the current request (headers + body).
  /// Used to preserve leftover bytes for the next pipelined request.
  func setRequestMessageSize(_ size: Int) {
    lock.lock()
    _requestMessageSize = size
    lock.unlock()
  }

  /// Set the total byte size of the current response (headers + body).
  func setResponseMessageSize(_ size: Int) {
    lock.lock()
    _responseMessageSize = size
    lock.unlock()
  }

  /// Check if the response body is fully received based on Content-Length or chunked encoding.
  /// Returns true if ready to reset for next request. Call this from the server→client task
  /// before calling resetForNextRequest() to avoid premature buffer clearing.
  func isResponseComplete() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    if _responseBodyComplete { return true }
    guard let respSize = _responseMessageSize else { return false }
    if _responseBuffer.count >= respSize {
      _responseBodyComplete = true
      return true
    }
    return false
  }

  /// Mark response body as complete (for chunked encoding where size isn't known up front).
  func markResponseBodyComplete(actualSize: Int) {
    lock.lock()
    _responseMessageSize = actualSize
    _responseBodyComplete = true
    lock.unlock()
  }

  /// Reset parsing state for the next request on a keep-alive connection.
  /// Preserves any leftover data beyond the current message boundaries
  /// (handles HTTP pipelining where the next request arrives before
  /// the current response completes).
  func resetForNextRequest() {
    lock.lock()
    // Preserve leftover request data beyond current message boundary
    if let reqSize = _requestMessageSize {
      if _requestBuffer.count > reqSize {
        _requestBuffer = Data(_requestBuffer[reqSize...])
      } else {
        _requestBuffer.removeAll(keepingCapacity: true)
      }
    }
    // If _requestMessageSize was never set, don't clear — data hasn't been parsed yet

    // Preserve leftover response data beyond current message boundary
    if let respSize = _responseMessageSize {
      if _responseBuffer.count > respSize {
        _responseBuffer = Data(_responseBuffer[respSize...])
      } else {
        _responseBuffer.removeAll(keepingCapacity: true)
      }
    }
    _hasRequest = false
    _hasResponse = false
    _responseBodyComplete = false
    _requestHeaderEndIndex = 0
    _requestIsChunked = false
    _requestCount += 1
    _currentFlowId = nil
    _requestMessageSize = nil
    _responseMessageSize = nil
    lock.unlock()
  }
}
