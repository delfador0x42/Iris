//
//  TLSSession+IOCallbacks.swift
//  IrisProxyExtension
//
//  SSL I/O callback functions and buffer management for TLSSession.
//

import Foundation
import Security
import NetworkExtension
import os.log

extension TLSSession {

    // MARK: - SSL I/O Buffer Methods

    /// Consumes data from the read buffer (called by SSL).
    func consumeFromBuffer(_ buffer: UnsafeMutableRawPointer, maxLength: Int) -> (Int, OSStatus) {
        readBufferLock.lock()

        if readBuffer.isEmpty {
            readBufferLock.unlock()

            if isClosed {
                return (0, errSSLClosedGraceful)
            }

            // Wait for data with timeout
            let result = dataAvailable.wait(timeout: .now() + .seconds(10))
            if result == .timedOut {
                return (0, OSStatus(errSSLWouldBlock))
            }

            readBufferLock.lock()
            if readBuffer.isEmpty {
                readBufferLock.unlock()
                if isClosed {
                    return (0, errSSLClosedGraceful)
                }
                return (0, OSStatus(errSSLWouldBlock))
            }
        }

        let bytesToRead = min(maxLength, readBuffer.count)
        readBuffer.copyBytes(to: buffer.assumingMemoryBound(to: UInt8.self), count: bytesToRead)
        readBuffer.removeFirst(bytesToRead)
        readBufferLock.unlock()

        return (bytesToRead, errSecSuccess)
    }

    /// Writes encrypted data to the flow (called by SSL).
    func writeToFlow(_ data: UnsafeRawPointer, length: Int) -> (Int, OSStatus) {
        let writeData = Data(bytes: data, count: length)

        let semaphore = DispatchSemaphore(value: 0)
        var writeError: Error?

        flow.write(writeData) { error in
            writeError = error
            semaphore.signal()
        }

        let result = semaphore.wait(timeout: .now() + .seconds(10))

        if result == .timedOut {
            return (0, OSStatus(errSSLWouldBlock))
        }

        if writeError != nil {
            return (0, errSSLClosedAbort)
        }

        return (length, errSecSuccess)
    }
}

// MARK: - SSL Callback Functions

/// SSL read callback - reads encrypted data from the flow's buffer.
func tlsReadFunc(
    connection: SSLConnectionRef,
    data: UnsafeMutableRawPointer,
    dataLength: UnsafeMutablePointer<Int>
) -> OSStatus {
    let session = Unmanaged<TLSSession>.fromOpaque(connection).takeUnretainedValue()
    let maxLength = dataLength.pointee

    let (bytesRead, status) = session.consumeFromBuffer(data, maxLength: maxLength)
    dataLength.pointee = bytesRead

    return status
}

/// SSL write callback - writes encrypted data to the flow.
func tlsWriteFunc(
    connection: SSLConnectionRef,
    data: UnsafeRawPointer,
    dataLength: UnsafeMutablePointer<Int>
) -> OSStatus {
    let session = Unmanaged<TLSSession>.fromOpaque(connection).takeUnretainedValue()
    let length = dataLength.pointee

    let (bytesWritten, status) = session.writeToFlow(data, length: length)
    dataLength.pointee = bytesWritten

    return status
}

// MARK: - Errors

enum TLSSessionError: Error, LocalizedError {
    case contextCreationFailed
    case configurationFailed(OSStatus)
    case certificateFailed(OSStatus)
    case handshakeFailed(OSStatus)
    case sessionClosed
    case connectionClosed
    case readFailed(OSStatus)
    case writeFailed(OSStatus)
    case timeout

    var errorDescription: String? {
        switch self {
        case .contextCreationFailed: return "Failed to create SSL context"
        case .configurationFailed(let status): return "SSL configuration failed: \(status)"
        case .certificateFailed(let status): return "SSL certificate setup failed: \(status)"
        case .handshakeFailed(let status): return "TLS handshake failed: \(status)"
        case .sessionClosed: return "TLS session is closed"
        case .connectionClosed: return "TLS connection closed by peer"
        case .readFailed(let status): return "TLS read failed: \(status)"
        case .writeFailed(let status): return "TLS write failed: \(status)"
        case .timeout: return "TLS operation timed out"
        }
    }
}
