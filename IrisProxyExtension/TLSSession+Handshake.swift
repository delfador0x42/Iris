//
//  TLSSession+Handshake.swift
//  IrisProxyExtension
//
//  TLS handshake using non-blocking retry loop (same pattern as read).
//  SSLHandshake returns errSSLWouldBlock when the read buffer is empty.
//  We release sslQueue, wait for data asynchronously, then retry.
//

import Foundation
import Security
import os.log

extension TLSSession {

    // MARK: - Handshake

    /// Handshake timeout in seconds
    static let handshakeTimeout: TimeInterval = 30

    func handshake() async throws {
        guard sslContext != nil else {
            throw TLSSessionError.sessionClosed
        }

        startFlowReader()

        let deadline = CFAbsoluteTimeGetCurrent() + Self.handshakeTimeout

        while true {
            guard !isClosed else { throw TLSSessionError.connectionClosed }
            if CFAbsoluteTimeGetCurrent() > deadline {
                logger.error("TLS handshake timed out")
                throw TLSSessionError.timeout
            }

            let status: OSStatus = await withCheckedContinuation { continuation in
                sslQueue.async { [weak self] in
                    guard let self = self, let ctx = self.sslContext else {
                        continuation.resume(returning: errSSLClosedAbort)
                        return
                    }
                    let s = SSLHandshake(ctx)
                    continuation.resume(returning: s)
                }
            }

            if status == errSecSuccess {
                logger.debug("TLS handshake completed successfully")
                return
            } else if status == errSSLWouldBlock {
                await waitForData()
                if isClosed { throw TLSSessionError.connectionClosed }
            } else if status == errSSLPeerAuthCompleted {
                continue
            } else {
                logger.error("TLS handshake failed: \(status)")
                throw TLSSessionError.handshakeFailed(status)
            }
        }
    }
}
