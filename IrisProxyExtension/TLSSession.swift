//
//  TLSSession.swift
//  IrisProxyExtension
//
//  Wraps SSLCreateContext to perform TLS over NEAppProxyTCPFlow's raw byte interface.
//  Used for the client-facing side of TLS MITM (presenting generated cert to client app).
//
//  NOTE: SSLCreateContext is deprecated since macOS 10.15 (TLS 1.2 max), but:
//  - It's the ONLY Apple API that works with arbitrary I/O callbacks
//  - TLS 1.2 is acceptable for local MITM (client is on same machine)
//  - Server-facing TLS uses NWConnection (TLS 1.3 capable)
//  - We only target macOS 26.2 where this API is still available
//

import Foundation
import Security
import NetworkExtension
import os.log

/// TLS session wrapping SSLCreateContext for use with NEAppProxyTCPFlow.
/// Bridges between SSL's synchronous read/write callbacks and NEAppProxyTCPFlow's
/// async completion-handler API using a ring buffer.
final class TLSSession {

    let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "TLSSession")

    /// The SSL context
    var sslContext: SSLContext?

    /// The flow providing raw bytes
    let flow: NEAppProxyTCPFlow

    /// Whether this is server-side (we present cert) or client-side
    let isServer: Bool

    /// Buffer for data read from the flow (available for SSL to consume)
    var readBuffer = Data()
    let readBufferLock = NSLock()

    /// Semaphore to signal when new data is available
    let dataAvailable = DispatchSemaphore(value: 0)

    /// Whether the flow is closed
    var isClosed = false

    /// Queue for blocking SSL operations
    let sslQueue = DispatchQueue(label: "com.wudan.iris.proxy.tls", qos: .userInitiated)

    // MARK: - Initialization

    /// Creates a TLS session.
    /// - Parameters:
    ///   - flow: The NEAppProxyTCPFlow to wrap
    ///   - identity: The SecIdentity to present (for server mode)
    ///   - isServer: Whether we're the TLS server (true) or client (false)
    init(flow: NEAppProxyTCPFlow, identity: SecIdentity? = nil, isServer: Bool) throws {
        self.flow = flow
        self.isServer = isServer

        // Create SSL context
        guard let ctx = SSLCreateContext(
            nil,
            isServer ? .serverSide : .clientSide,
            .streamType
        ) else {
            throw TLSSessionError.contextCreationFailed
        }
        self.sslContext = ctx

        // Set I/O callbacks
        let status = SSLSetIOFuncs(ctx, tlsReadFunc, tlsWriteFunc)
        guard status == errSecSuccess else {
            throw TLSSessionError.configurationFailed(status)
        }

        // Set connection ref (self pointer for callbacks)
        let connectionRef = Unmanaged.passUnretained(self).toOpaque()
        let refStatus = SSLSetConnection(ctx, connectionRef)
        guard refStatus == errSecSuccess else {
            throw TLSSessionError.configurationFailed(refStatus)
        }

        // Set certificate for server mode
        if isServer, let identity = identity {
            let certArray = [identity] as CFArray
            let certStatus = SSLSetCertificate(ctx, certArray)
            guard certStatus == errSecSuccess else {
                throw TLSSessionError.certificateFailed(certStatus)
            }
        }

        // For client mode, accept any server cert (we're connecting to the real server)
        if !isServer {
            SSLSetSessionOption(ctx, .breakOnServerAuth, true)
        }

        logger.debug("TLS session created (isServer: \(isServer))")
    }

    deinit {
        close()
    }

    // MARK: - Close

    func close() {
        guard let ctx = sslContext else { return }

        SSLClose(ctx)
        sslContext = nil
        isClosed = true

        // Signal any waiting reads
        dataAvailable.signal()

        logger.debug("TLS session closed")
    }
}
