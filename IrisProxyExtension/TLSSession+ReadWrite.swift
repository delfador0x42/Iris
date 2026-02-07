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

    /// Writes data to the TLS session (encrypts and sends).
    func write(_ data: Data) async throws {
        guard sslContext != nil else {
            throw TLSSessionError.sessionClosed
        }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            sslQueue.async { [weak self] in
                guard let self = self, let ctx = self.sslContext else {
                    continuation.resume(throwing: TLSSessionError.sessionClosed)
                    return
                }

                var totalWritten = 0
                let bytes = [UInt8](data)

                while totalWritten < bytes.count {
                    var bytesWritten = 0
                    let remaining = bytes.count - totalWritten

                    let status = bytes.withUnsafeBufferPointer { buffer in
                        SSLWrite(
                            ctx,
                            buffer.baseAddress!.advanced(by: totalWritten),
                            remaining,
                            &bytesWritten
                        )
                    }

                    totalWritten += bytesWritten

                    if status != errSecSuccess && status != errSSLWouldBlock {
                        self.logger.error("TLS write error: \(status)")
                        continuation.resume(throwing: TLSSessionError.writeFailed(status))
                        return
                    }
                }

                continuation.resume()
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
            self.readBuffer.append(data)
            self.readBufferLock.unlock()

            self.signalDataAvailable()
            self.readFromFlow()
        }
    }
}
