//
//  TLSInterceptor.swift
//  IrisProxyExtension
//
//  Handles TLS interception for HTTPS traffic.
//  Generates per-host certificates signed by the Iris CA.
//

import Foundation
import Security
import Network
import os.log

/// Handles TLS interception for HTTPS connections.
/// Uses the Iris CA certificate to generate per-host certificates on demand.
final class TLSInterceptor: @unchecked Sendable {

    let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "TLSInterceptor")

    /// CA private key (set via XPC from main app — extension can't access keychain)
    /// Access under caLock only.
    var caPrivateKey: SecKey?

    /// CA certificate (set via XPC from main app). Access under caLock only.
    var caCertificate: SecCertificate?

    /// Lock protecting CA key+cert writes and reads (must be atomic pair)
    let caLock = NSLock()

    /// Certificate cache to avoid regenerating certificates
    var certificateCache: [String: (identity: SecIdentity, certificate: SecCertificate)] = [:]
    let cacheLock = NSLock()
    let maxCacheSize = 1000

    /// Whether interception is available (CA loaded). Thread-safe.
    var isAvailable: Bool {
        caLock.lock()
        defer { caLock.unlock() }
        return caPrivateKey != nil && caCertificate != nil
    }

    /// Set the CA from raw data sent via XPC from the main app.
    /// Extension runs as root and can't access secd/keychain — XPC is the only path.
    func setCA(certData: Data, keyData: Data) -> Bool {
        let keyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateWithData(keyData as CFData, keyAttributes as CFDictionary, &error) else {
            logger.error("Failed to create SecKey from XPC data: \(error?.takeRetainedValue().localizedDescription ?? "unknown")")
            return false
        }

        guard let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
            logger.error("Failed to create SecCertificate from XPC data")
            return false
        }

        caLock.lock()
        self.caPrivateKey = privateKey
        self.caCertificate = certificate
        caLock.unlock()
        logger.info("CA loaded via XPC — TLS interception is now available")
        return true
    }

    // MARK: - Certificate Cache

    /// Gets or generates a certificate for a hostname.
    /// Double-checked locking prevents duplicate generation for the same host.
    func getCertificate(for hostname: String) -> (identity: SecIdentity, certificate: SecCertificate)? {
        cacheLock.lock()
        if let cached = certificateCache[hostname] {
            cacheLock.unlock()
            return cached
        }
        cacheLock.unlock()

        guard let result = generateCertificate(for: hostname) else { return nil }

        cacheLock.lock()
        // Re-check: another thread may have generated while we were unlocked
        if let existing = certificateCache[hostname] {
            cacheLock.unlock()
            return existing
        }
        if certificateCache.count >= maxCacheSize {
            let keysToRemove = Array(certificateCache.keys.prefix(maxCacheSize / 2))
            for key in keysToRemove { certificateCache.removeValue(forKey: key) }
        }
        certificateCache[hostname] = result
        cacheLock.unlock()

        return result
    }

    // MARK: - TLS Options

    /// Creates TLS parameters for client-side connection (proxy to real server).
    func createClientTLSParameters(for hostname: String) -> NWParameters {
        let tlsOptions = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { _, trust, complete in
            complete(true)
        }, .main)
        sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, hostname)
        let tcpOptions = NWProtocolTCP.Options()
        return NWParameters(tls: tlsOptions, tcp: tcpOptions)
    }

    /// Creates TLS parameters for server-side connection (app to proxy).
    func createServerTLSParameters(for hostname: String) -> NWParameters? {
        guard let (identity, _) = getCertificate(for: hostname) else { return nil }
        let tlsOptions = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tlsOptions.securityProtocolOptions, sec_identity_create(identity)!)
        let tcpOptions = NWProtocolTCP.Options()
        return NWParameters(tls: tlsOptions, tcp: tcpOptions)
    }
}
