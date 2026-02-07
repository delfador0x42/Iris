//
//  TLSSession+Handshake.swift
//  IrisProxyExtension
//
//  TLS handshake implementation.
//

import Foundation
import Security
import os.log

extension TLSSession {

    // MARK: - Handshake

    /// Performs the TLS handshake.
    /// This must be called from a background queue (it blocks).
    func handshake() async throws {
        guard let ctx = sslContext else {
            throw TLSSessionError.sessionClosed
        }

        // Start reading from flow in background
        startFlowReader()

        // Perform handshake on SSL queue (blocking)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            sslQueue.async { [weak self] in
                guard let self = self, let ctx = self.sslContext else {
                    continuation.resume(throwing: TLSSessionError.sessionClosed)
                    return
                }

                var status: OSStatus
                repeat {
                    status = SSLHandshake(ctx)

                    if status == errSSLPeerAuthCompleted {
                        // Client mode: we got server auth callback, accept and continue
                        continue
                    }
                } while status == errSSLWouldBlock

                if status == errSecSuccess {
                    self.logger.debug("TLS handshake completed successfully")
                    continuation.resume()
                } else {
                    self.logger.error("TLS handshake failed: \(status)")
                    continuation.resume(throwing: TLSSessionError.handshakeFailed(status))
                }
            }
        }
    }
}
