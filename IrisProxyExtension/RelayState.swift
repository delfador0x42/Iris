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
        _requestBuffer.append(data)
        lock.unlock()
    }

    func appendToResponseBuffer(_ data: Data) {
        lock.lock()
        _responseBuffer.append(data)
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

    func markRequestCaptured() {
        lock.lock()
        _hasRequest = true
        lock.unlock()
    }

    func markResponseCaptured() {
        lock.lock()
        _hasResponse = true
        lock.unlock()
    }
}
