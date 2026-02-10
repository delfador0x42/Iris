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

    /// Shared CA private key (loaded from Keychain)
    var caPrivateKey: SecKey?

    /// Shared CA certificate
    var caCertificate: SecCertificate?

    /// Certificate cache to avoid regenerating certificates
    var certificateCache: [String: (identity: SecIdentity, certificate: SecCertificate)] = [:]
    let cacheLock = NSLock()
    let maxCacheSize = 1000

    /// Whether interception is available (CA loaded)
    var isAvailable: Bool {
        caPrivateKey != nil && caCertificate != nil
    }

    init() {
        loadCA()
    }

    /// Loads the CA certificate and private key from Keychain.
    private func loadCA() {
        logger.info("Loading CA certificate from Keychain...")

        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "Iris Proxy CA Private Key".data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnRef as String: true
        ]

        var keyResult: CFTypeRef?
        let keyStatus = SecItemCopyMatching(keyQuery as CFDictionary, &keyResult)

        if keyStatus == errSecSuccess, let ref = keyResult,
           CFGetTypeID(ref) == SecKeyGetTypeID() {
            caPrivateKey = (ref as! SecKey)
            logger.info("Loaded CA private key from Keychain")
        } else {
            logger.warning("CA private key not found in Keychain (status: \(keyStatus))")
        }

        let certQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: "Iris Proxy CA Certificate",
            kSecReturnRef as String: true
        ]

        var certResult: CFTypeRef?
        let certStatus = SecItemCopyMatching(certQuery as CFDictionary, &certResult)

        if certStatus == errSecSuccess, let ref = certResult,
           CFGetTypeID(ref) == SecCertificateGetTypeID() {
            caCertificate = (ref as! SecCertificate)
            logger.info("Loaded CA certificate from Keychain")
        } else {
            logger.warning("CA certificate not found in Keychain (status: \(certStatus))")
        }

        if isAvailable {
            logger.info("TLS interception is available")
        } else {
            logger.warning("TLS interception is NOT available - CA not loaded")
        }
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
