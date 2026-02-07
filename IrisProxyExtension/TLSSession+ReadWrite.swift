//
//  TLSSession+ReadWrite.swift
//  IrisProxyExtension
//
//  TLS read/write operations and flow reader.
//

import Foundation
import Security
import NetworkExtension
import os.log

extension TLSSession {

    // MARK: - Read

    /// Reads decrypted data from the TLS session.
    func read(maxLength: Int = 65536) async throws -> Data {
        guard let ctx = sslContext else {
            throw TLSSessionError.sessionClosed
        }

        return try await withCheckedThrowingContinuation { continuation in
            sslQueue.async { [weak self] in
                guard let self = self, let ctx = self.sslContext else {
                    continuation.resume(throwing: TLSSessionError.sessionClosed)
                    return
                }

                var buffer = [UInt8](repeating: 0, count: maxLength)
                var bytesRead = 0

                let status = SSLRead(ctx, &buffer, maxLength, &bytesRead)

                if status == errSecSuccess || (status == errSSLWouldBlock && bytesRead > 0) {
                    continuation.resume(returning: Data(buffer[..<bytesRead]))
                } else if status == errSSLClosedGraceful || status == errSSLClosedAbort {
                    continuation.resume(throwing: TLSSessionError.connectionClosed)
                } else {
                    self.logger.error("TLS read error: \(status)")
                    continuation.resume(throwing: TLSSessionError.readFailed(status))
                }
            }
        }
    }

    // MARK: - Write

    /// Writes data to the TLS session (encrypts and sends).
    func write(_ data: Data) async throws {
        guard let ctx = sslContext else {
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
                self.dataAvailable.signal()
                return
            }

            guard let data = data, !data.isEmpty else {
                self.isClosed = true
                self.dataAvailable.signal()
                return
            }

            // Append to read buffer
            self.readBufferLock.lock()
            self.readBuffer.append(data)
            self.readBufferLock.unlock()

            // Signal that data is available
            self.dataAvailable.signal()

            // Continue reading
            self.readFromFlow()
        }
    }
}
