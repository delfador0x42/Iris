//
//  TLSSession+ReadWrite.swift
//  IrisProxyExtension
//
//  TLS read/write operations and flow reader.
//  Read uses a non-blocking retry loop: tries SSLRead on sslQueue, if buffer is empty
//  (errSSLWouldBlock), releases sslQueue and waits asynchronously for data, then retries.
//  This prevents deadlock: write() can use sslQueue while read() is waiting for data.
//

import Foundation
import Security
import NetworkExtension
import os.log

extension TLSSession {

    /// Result of a single SSLRead attempt
    enum SSLReadResult {
        case data(Data)
        case wouldBlock
        case closed
        case error(OSStatus)
    }

    // MARK: - Read

    /// Reads decrypted data from the TLS session.
    /// Non-blocking retry loop: tries SSLRead, if no data available, waits
    /// asynchronously (releasing sslQueue), then retries.
    func read(maxLength: Int = 65536) async throws -> Data {
        while true {
            guard !isClosed else { throw TLSSessionError.connectionClosed }
            guard sslContext != nil else { throw TLSSessionError.sessionClosed }

            let result: SSLReadResult = await withCheckedContinuation { continuation in
                sslQueue.async { [weak self] in
                    guard let self = self, let ctx = self.sslContext else {
                        continuation.resume(returning: .closed)
                        return
                    }

                    var buffer = [UInt8](repeating: 0, count: maxLength)
                    var bytesRead = 0
                    let status = SSLRead(ctx, &buffer, maxLength, &bytesRead)

                    if status == errSecSuccess || (status == errSSLWouldBlock && bytesRead > 0) {
                        continuation.resume(returning: .data(Data(buffer[..<bytesRead])))
                    } else if status == errSSLWouldBlock {
                        continuation.resume(returning: .wouldBlock)
                    } else if status == errSSLClosedGraceful || status == errSSLClosedAbort {
                        continuation.resume(returning: .closed)
                    } else {
                        continuation.resume(returning: .error(status))
                    }
                }
            }

            switch result {
            case .data(let data):
                return data
            case .wouldBlock:
                // sslQueue is now free — write() can proceed while we wait
                await waitForData()
                // Re-check after waking — prevents livelock when isClosed
                // changed between the top guard and the SSLRead dispatch
                if isClosed { throw TLSSessionError.connectionClosed }
            case .closed:
                throw TLSSessionError.connectionClosed
            case .error(let status):
                logger.error("TLS read error: \(status)")
                throw TLSSessionError.readFailed(status)
            }
        }
    }

    // MARK: - Write

    /// Result of a single SSLWrite attempt on sslQueue
    private enum SSLWriteResult {
        case complete
        case partial(Int)     // bytes written so far
        case wouldBlock(Int)  // bytes written so far, need async wait
        case closed
        case error(OSStatus)
    }

    /// Writes data to the TLS session (encrypts and sends).
    /// Uses async retry loop matching read()'s pattern — releases sslQueue
    /// between attempts so read() isn't blocked.
    func write(_ data: Data) async throws {
        let bytes = [UInt8](data)
        var totalWritten = 0
        var wouldBlockRetries = 0
        let maxRetries = 100

        while totalWritten < bytes.count {
            guard !isClosed else { throw TLSSessionError.connectionClosed }
            guard sslContext != nil else { throw TLSSessionError.sessionClosed }

            let offset = totalWritten
            let result: SSLWriteResult = await withCheckedContinuation { continuation in
                sslQueue.async { [weak self] in
                    guard let self = self, let ctx = self.sslContext else {
                        continuation.resume(returning: .closed)
                        return
                    }

                    var bytesWritten = 0
                    let remaining = bytes.count - offset
                    let status = bytes.withUnsafeBufferPointer { buffer in
                        SSLWrite(ctx, buffer.baseAddress!.advanced(by: offset),
                                 remaining, &bytesWritten)
                    }

                    if status == errSecSuccess {
                        continuation.resume(returning: .complete)
                    } else if status == errSSLWouldBlock && bytesWritten > 0 {
                        continuation.resume(returning: .partial(bytesWritten))
                    } else if status == errSSLWouldBlock {
                        continuation.resume(returning: .wouldBlock(0))
                    } else if status == errSSLClosedGraceful || status == errSSLClosedAbort {
                        continuation.resume(returning: .closed)
                    } else {
                        continuation.resume(returning: .error(status))
                    }
                }
            }

            switch result {
            case .complete:
                return  // SSLWrite consumed all remaining bytes
            case .partial(let n):
                totalWritten += n
                wouldBlockRetries = 0
            case .wouldBlock:
                wouldBlockRetries += 1
                if wouldBlockRetries > maxRetries {
                    logger.error("TLS write: too many retries")
                    throw TLSSessionError.writeFailed(errSSLWouldBlock)
                }
                // Async sleep — releases sslQueue so read() can proceed
                try? await Task.sleep(nanoseconds: 1_000_000)  // 1ms
            case .closed:
                throw TLSSessionError.connectionClosed
            case .error(let status):
                logger.error("TLS write error: \(status)")
                throw TLSSessionError.writeFailed(status)
            }
        }
    }

    // MARK: - Flow Reader

    /// Continuously reads from the NEAppProxyTCPFlow and buffers data for SSL.
    func startFlowReader() {
        readFromFlow()
    }

    func readFromFlow() {
        guard !isClosed else { return }

        flow.readData { [weak self] data, error in
            guard let self = self else { return }

            if let error = error {
                let nsError = error as NSError
                if nsError.code != NEAppProxyFlowError.notConnected.rawValue {
                    self.logger.error("Flow read error: \(error.localizedDescription)")
                }
                self.isClosed = true
                self.signalDataAvailable()
                return
            }

            guard let data = data, !data.isEmpty else {
                self.isClosed = true
                self.signalDataAvailable()
                return
            }

            self.readBufferLock.lock()
            defer { self.readBufferLock.unlock() }
            self.readBuffer.append(data)
            if self.readBuffer.count > 16 * 1024 * 1024 {
                self.logger.warning("TLS read buffer exceeded 16MB, closing session")
                self.readBuffer.removeAll()
                self.isClosed = true
            }

            self.signalDataAvailable()
            self.readFromFlow()
        }
    }
}
