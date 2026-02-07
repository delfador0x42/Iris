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

    func handshake() async throws {
        guard sslContext != nil else {
            throw TLSSessionError.sessionClosed
        }

        startFlowReader()

        while true {
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
                // Buffer was empty — wait for flow reader to deliver data
                await waitForData()
            } else if status == errSSLPeerAuthCompleted {
                // Client mode: server auth callback, continue handshake
                continue
            } else {
                logger.error("TLS handshake failed: \(status)")
                throw TLSSessionError.handshakeFailed(status)
            }
        }
    }
}
