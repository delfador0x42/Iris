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
/// Uses non-blocking I/O callbacks with async continuation-based signaling
/// to avoid deadlocking the SSL queue between concurrent read and write.
final class TLSSession {

    let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "TLSSession")

    /// The SSL context
    var sslContext: SSLContext?

    /// Retained self reference for SSL callbacks (prevents use-after-free)
    private var retainedRef: Unmanaged<TLSSession>?

    /// The flow providing raw bytes
    let flow: NEAppProxyTCPFlow

    /// Whether this is server-side (we present cert) or client-side
    let isServer: Bool

    /// Buffer for data read from the flow (available for SSL to consume)
    var readBuffer = Data()
    let readBufferLock = NSLock()

    /// Async waiters for new data (replaces DispatchSemaphore)
    var dataWaiters: [CheckedContinuation<Void, Never>] = []
    let waiterLock = NSLock()

    /// Whether the flow is closed
    var isClosed = false

    /// Queue for SSL operations (read and write are serialized through here)
    let sslQueue = DispatchQueue(label: "com.wudan.iris.proxy.tls", qos: .userInitiated)

    // MARK: - Initialization

    init(flow: NEAppProxyTCPFlow, identity: SecIdentity? = nil, isServer: Bool) throws {
        self.flow = flow
        self.isServer = isServer

        guard let ctx = SSLCreateContext(
            nil,
            isServer ? .serverSide : .clientSide,
            .streamType
        ) else {
            throw TLSSessionError.contextCreationFailed
        }
        self.sslContext = ctx

        let status = SSLSetIOFuncs(ctx, tlsReadFunc, tlsWriteFunc)
        guard status == errSecSuccess else {
            throw TLSSessionError.configurationFailed(status)
        }

        let retained = Unmanaged.passRetained(self)
        self.retainedRef = retained
        let connectionRef = retained.toOpaque()
        let refStatus = SSLSetConnection(ctx, connectionRef)
        guard refStatus == errSecSuccess else {
            throw TLSSessionError.configurationFailed(refStatus)
        }

        if isServer, let identity = identity {
            let certArray = [identity] as CFArray
            let certStatus = SSLSetCertificate(ctx, certArray)
            guard certStatus == errSecSuccess else {
                throw TLSSessionError.certificateFailed(certStatus)
            }
        }

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
        // Run SSLClose on sslQueue to prevent racing with SSLRead/SSLWrite
        sslQueue.sync { [weak self] in
            guard let self = self, let ctx = self.sslContext else { return }
            SSLClose(ctx)
            self.sslContext = nil
        }
        isClosed = true

        retainedRef?.release()
        retainedRef = nil

        signalDataAvailable()

        logger.debug("TLS session closed")
    }

    // MARK: - Async Data Signaling

    /// Checks if data is available or session is closed (synchronous, lock-safe).
    private func hasBufferedDataOrClosed() -> Bool {
        readBufferLock.lock()
        defer { readBufferLock.unlock() }
        return !readBuffer.isEmpty || isClosed
    }

    /// Waits asynchronously for new data in the read buffer.
    /// Does NOT hold sslQueue, allowing writes to proceed.
    func waitForData() async {
        if hasBufferedDataOrClosed() { return }

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            waiterLock.lock()
            // Double-check after acquiring lock
            readBufferLock.lock()
            if !readBuffer.isEmpty || isClosed {
                readBufferLock.unlock()
                waiterLock.unlock()
                continuation.resume()
                return
            }
            readBufferLock.unlock()
            dataWaiters.append(continuation)
            waiterLock.unlock()
        }
    }

    /// Wakes all tasks waiting for data.
    func signalDataAvailable() {
        waiterLock.lock()
        let waiters = dataWaiters
        dataWaiters.removeAll()
        waiterLock.unlock()
        for waiter in waiters {
            waiter.resume()
        }
    }
}
