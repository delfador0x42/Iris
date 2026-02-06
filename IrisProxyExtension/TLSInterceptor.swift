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

    private let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "TLSInterceptor")

    /// Shared CA private key (loaded from Keychain)
    private var caPrivateKey: SecKey?

    /// Shared CA certificate
    private var caCertificate: SecCertificate?

    /// Certificate cache to avoid regenerating certificates
    private var certificateCache: [String: (identity: SecIdentity, certificate: SecCertificate)] = [:]
    private let cacheLock = NSLock()
    private let maxCacheSize = 1000

    /// Whether interception is available (CA loaded)
    var isAvailable: Bool {
        caPrivateKey != nil && caCertificate != nil
    }

    // MARK: - Initialization

    init() {
        loadCA()
    }

    /// Loads the CA certificate and private key from Keychain.
    private func loadCA() {
        logger.info("Loading CA certificate from Keychain...")

        // Load CA private key
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "Iris Proxy CA Private Key".data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnRef as String: true
        ]

        var keyResult: CFTypeRef?
        let keyStatus = SecItemCopyMatching(keyQuery as CFDictionary, &keyResult)

        if keyStatus == errSecSuccess, let key = keyResult {
            caPrivateKey = (key as! SecKey)
            logger.info("Loaded CA private key from Keychain")
        } else {
            logger.warning("CA private key not found in Keychain (status: \(keyStatus))")
        }

        // Load CA certificate
        let certQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: "Iris Proxy CA Certificate",
            kSecReturnRef as String: true
        ]

        var certResult: CFTypeRef?
        let certStatus = SecItemCopyMatching(certQuery as CFDictionary, &certResult)

        if certStatus == errSecSuccess, let cert = certResult {
            caCertificate = (cert as! SecCertificate)
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

    // MARK: - Certificate Generation

    /// Gets or generates a certificate for a hostname.
    func getCertificate(for hostname: String) -> (identity: SecIdentity, certificate: SecCertificate)? {
        // Check cache first
        cacheLock.lock()
        if let cached = certificateCache[hostname] {
            cacheLock.unlock()
            logger.debug("Using cached certificate for \(hostname)")
            return cached
        }
        cacheLock.unlock()

        // Generate new certificate
        guard let result = generateCertificate(for: hostname) else {
            return nil
        }

        // Cache it
        cacheLock.lock()
        if certificateCache.count >= maxCacheSize {
            // Remove oldest entries (simple approach - just clear half)
            let keysToRemove = Array(certificateCache.keys.prefix(maxCacheSize / 2))
            for key in keysToRemove {
                certificateCache.removeValue(forKey: key)
            }
        }
        certificateCache[hostname] = result
        cacheLock.unlock()

        return result
    }

    /// Generates a new certificate for a hostname.
    private func generateCertificate(for hostname: String) -> (identity: SecIdentity, certificate: SecCertificate)? {
        guard let caPrivateKey = caPrivateKey,
              let caCertificate = caCertificate else {
            logger.error("Cannot generate certificate - CA not available")
            return nil
        }

        logger.debug("Generating certificate for \(hostname)")

        // Generate new key pair for this certificate
        let keyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrIsPermanent as String: false
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &error) else {
            logger.error("Failed to generate key pair: \(error?.takeRetainedValue().localizedDescription ?? "unknown")")
            return nil
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            logger.error("Failed to extract public key")
            return nil
        }

        // Build certificate
        guard let certificateData = buildLeafCertificate(
            hostname: hostname,
            publicKey: publicKey,
            caPrivateKey: caPrivateKey,
            caCertificate: caCertificate
        ) else {
            logger.error("Failed to build certificate")
            return nil
        }

        guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            logger.error("Failed to create SecCertificate")
            return nil
        }

        // Create identity by adding to temporary keychain
        guard let identity = createIdentity(privateKey: privateKey, certificate: certificate) else {
            logger.error("Failed to create identity")
            return nil
        }

        logger.debug("Successfully generated certificate for \(hostname)")
        return (identity, certificate)
    }

    /// Creates a SecIdentity from a private key and certificate.
    private func createIdentity(privateKey: SecKey, certificate: SecCertificate) -> SecIdentity? {
        // Add private key to keychain temporarily
        let keyTag = "com.wudan.iris.proxy.temp.\(UUID().uuidString)"
        let addKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag.data(using: .utf8)!,
            kSecValueRef as String: privateKey,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        var status = SecItemAdd(addKeyQuery as CFDictionary, nil)
        if status != errSecSuccess && status != errSecDuplicateItem {
            logger.error("Failed to add private key to keychain: \(status)")
            return nil
        }

        // Add certificate to keychain temporarily
        let addCertQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        status = SecItemAdd(addCertQuery as CFDictionary, nil)
        if status != errSecSuccess && status != errSecDuplicateItem {
            // Clean up key
            SecItemDelete(addKeyQuery as CFDictionary)
            logger.error("Failed to add certificate to keychain: \(status)")
            return nil
        }

        // Get identity
        let identityQuery: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var identityRef: CFTypeRef?
        status = SecItemCopyMatching(identityQuery as CFDictionary, &identityRef)

        // Clean up temporary items
        SecItemDelete(addKeyQuery as CFDictionary)
        SecItemDelete(addCertQuery as CFDictionary)

        if status == errSecSuccess, let identity = identityRef {
            return (identity as! SecIdentity)
        }

        return nil
    }

    // MARK: - Certificate Building

    /// Builds a leaf certificate for a hostname.
    private func buildLeafCertificate(
        hostname: String,
        publicKey: SecKey,
        caPrivateKey: SecKey,
        caCertificate: SecCertificate
    ) -> Data? {
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            return nil
        }

        let now = Date()
        let notBefore = now.addingTimeInterval(-2 * 24 * 60 * 60)
        let notAfter = now.addingTimeInterval(365 * 24 * 60 * 60)

        let serialNumber = generateSerialNumber()

        // Get issuer name from CA certificate
        guard let issuerName = extractSubjectName(from: caCertificate) else {
            return nil
        }

        // Build TBS certificate
        var tbsCertificate = Data()

        // Version (v3 = 2)
        tbsCertificate.append(contentsOf: buildExplicitTag(0, content: buildInteger(2)))

        // Serial number
        tbsCertificate.append(contentsOf: buildInteger(serialNumber))

        // Signature algorithm (SHA256 with RSA)
        tbsCertificate.append(contentsOf: buildSignatureAlgorithm())

        // Issuer
        tbsCertificate.append(contentsOf: issuerName)

        // Validity
        tbsCertificate.append(contentsOf: buildValidity(notBefore: notBefore, notAfter: notAfter))

        // Subject (hostname as CN)
        tbsCertificate.append(contentsOf: buildDistinguishedName(commonName: hostname))

        // Subject Public Key Info
        tbsCertificate.append(contentsOf: buildSubjectPublicKeyInfo(publicKeyData: publicKeyData))

        // Extensions
        let extensions = buildLeafExtensions(hostname: hostname)
        tbsCertificate.append(contentsOf: buildExplicitTag(3, content: buildSequence(extensions)))

        // Wrap TBS in sequence
        let tbsSequence = buildSequence(tbsCertificate)

        // Sign with CA private key
        guard let signature = signData(Data(tbsSequence), with: caPrivateKey) else {
            return nil
        }

        // Build final certificate
        var certificate = Data()
        certificate.append(contentsOf: tbsSequence)
        certificate.append(contentsOf: buildSignatureAlgorithm())
        certificate.append(contentsOf: buildBitString(signature))

        return Data(buildSequence(certificate))
    }

    // MARK: - ASN.1 Encoding Helpers

    private func generateSerialNumber() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        bytes[0] &= 0x7F
        return Data(bytes)
    }

    private func buildInteger(_ value: Int) -> [UInt8] {
        var result: [UInt8] = [0x02]
        if value == 0 {
            result.append(1)
            result.append(0)
        } else {
            var bytes: [UInt8] = []
            var v = value
            while v > 0 {
                bytes.insert(UInt8(v & 0xFF), at: 0)
                v >>= 8
            }
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, at: 0)
            }
            result.append(contentsOf: encodeLength(bytes.count))
            result.append(contentsOf: bytes)
        }
        return result
    }

    private func buildInteger(_ data: Data) -> [UInt8] {
        var result: [UInt8] = [0x02]
        var bytes = [UInt8](data)
        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }
        result.append(contentsOf: encodeLength(bytes.count))
        result.append(contentsOf: bytes)
        return result
    }

    private func buildSequence(_ content: Data) -> [UInt8] {
        var result: [UInt8] = [0x30]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    private func buildSequence(_ content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [0x30]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    private func buildBitString(_ data: Data) -> [UInt8] {
        var result: [UInt8] = [0x03]
        result.append(contentsOf: encodeLength(data.count + 1))
        result.append(0)
        result.append(contentsOf: data)
        return result
    }

    private func buildOID(_ oid: [UInt]) -> [UInt8] {
        var result: [UInt8] = [0x06]
        var content: [UInt8] = []
        if oid.count >= 2 {
            content.append(UInt8(oid[0] * 40 + oid[1]))
            for i in 2..<oid.count {
                content.append(contentsOf: encodeOIDComponent(oid[i]))
            }
        }
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    private func encodeOIDComponent(_ value: UInt) -> [UInt8] {
        if value < 128 {
            return [UInt8(value)]
        }
        var bytes: [UInt8] = []
        var v = value
        while v > 0 {
            bytes.insert(UInt8(v & 0x7F) | (bytes.isEmpty ? 0 : 0x80), at: 0)
            v >>= 7
        }
        return bytes
    }

    private func buildUTF8String(_ string: String) -> [UInt8] {
        let data = Data(string.utf8)
        var result: [UInt8] = [0x0C]
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    private func buildUTCTime(_ date: Date) -> [UInt8] {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        formatter.timeZone = TimeZone(identifier: "UTC")
        let dateString = formatter.string(from: date)
        let data = Data(dateString.utf8)
        var result: [UInt8] = [0x17]
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    private func buildExplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [UInt8(0xA0 + tag)]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    private func buildImplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [UInt8(0x80 + tag)]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    private func encodeLength(_ length: Int) -> [UInt8] {
        if length < 128 {
            return [UInt8(length)]
        }
        var bytes: [UInt8] = []
        var len = length
        while len > 0 {
            bytes.insert(UInt8(len & 0xFF), at: 0)
            len >>= 8
        }
        return [UInt8(0x80 + bytes.count)] + bytes
    }

    private func buildSignatureAlgorithm() -> [UInt8] {
        let oid = buildOID([1, 2, 840, 113549, 1, 1, 11])
        let null: [UInt8] = [0x05, 0x00]
        var content = Data()
        content.append(contentsOf: oid)
        content.append(contentsOf: null)
        return buildSequence(content)
    }

    private func buildDistinguishedName(commonName: String) -> [UInt8] {
        var rdnSequence = Data()
        let cnOID = buildOID([2, 5, 4, 3])
        let cnValue = buildUTF8String(commonName)
        var cnAttrValue = Data()
        cnAttrValue.append(contentsOf: cnOID)
        cnAttrValue.append(contentsOf: cnValue)
        let cnSet = buildSet(buildSequence(cnAttrValue))
        rdnSequence.append(contentsOf: cnSet)
        return buildSequence(rdnSequence)
    }

    private func buildSet(_ content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [0x31]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    private func buildValidity(notBefore: Date, notAfter: Date) -> [UInt8] {
        var content = Data()
        content.append(contentsOf: buildUTCTime(notBefore))
        content.append(contentsOf: buildUTCTime(notAfter))
        return buildSequence(content)
    }

    private func buildSubjectPublicKeyInfo(publicKeyData: Data) -> [UInt8] {
        let rsaOID = buildOID([1, 2, 840, 113549, 1, 1, 1])
        let null: [UInt8] = [0x05, 0x00]
        var algorithm = Data()
        algorithm.append(contentsOf: rsaOID)
        algorithm.append(contentsOf: null)
        let algorithmSequence = buildSequence(algorithm)
        let publicKeySequence = buildSequence(publicKeyData)
        let publicKeyBitString = buildBitString(Data(publicKeySequence))
        var content = Data()
        content.append(contentsOf: algorithmSequence)
        content.append(contentsOf: publicKeyBitString)
        return buildSequence(content)
    }

    private func buildLeafExtensions(hostname: String) -> Data {
        var extensions = Data()

        // Basic Constraints (CA: false)
        let bcOID = buildOID([2, 5, 29, 19])
        let bcValueSequence = buildSequence(Data())
        let bcOctetString = buildOctetString(Data(bcValueSequence))
        var bcExtension = Data()
        bcExtension.append(contentsOf: bcOID)
        bcExtension.append(contentsOf: bcOctetString)
        extensions.append(contentsOf: buildSequence(bcExtension))

        // Extended Key Usage (serverAuth)
        let ekuOID = buildOID([2, 5, 29, 37])
        let serverAuthOID = buildOID([1, 3, 6, 1, 5, 5, 7, 3, 1])
        let ekuValueSequence = buildSequence(serverAuthOID)
        let ekuOctetString = buildOctetString(Data(ekuValueSequence))
        var ekuExtension = Data()
        ekuExtension.append(contentsOf: ekuOID)
        ekuExtension.append(contentsOf: ekuOctetString)
        extensions.append(contentsOf: buildSequence(ekuExtension))

        // Subject Alternative Name
        let sanOID = buildOID([2, 5, 29, 17])
        let dnsName = buildImplicitTag(2, content: [UInt8](hostname.utf8))
        let sanValueSequence = buildSequence(dnsName)
        let sanOctetString = buildOctetString(Data(sanValueSequence))
        var sanExtension = Data()
        sanExtension.append(contentsOf: sanOID)
        sanExtension.append(contentsOf: sanOctetString)
        extensions.append(contentsOf: buildSequence(sanExtension))

        return extensions
    }

    private func buildOctetString(_ data: Data) -> [UInt8] {
        var result: [UInt8] = [0x04]
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    private func extractSubjectName(from certificate: SecCertificate) -> [UInt8]? {
        guard let certData = SecCertificateCopyData(certificate) as Data? else {
            return nil
        }

        let bytes = [UInt8](certData)
        guard bytes.count > 4, bytes[0] == 0x30 else {
            return nil
        }

        // Simplified parsing - extract subject name from certificate
        // This is a basic implementation that works for most certificates
        var offset = 1
        _ = parseLength(bytes, offset: &offset)

        guard bytes[offset] == 0x30 else { return nil }
        offset += 1
        _ = parseLength(bytes, offset: &offset)

        // Skip version if present
        if bytes[offset] == 0xA0 {
            offset += 1
            let vLen = parseLength(bytes, offset: &offset)
            offset += vLen
        }

        // Skip serial number
        guard bytes[offset] == 0x02 else { return nil }
        offset += 1
        let serialLen = parseLength(bytes, offset: &offset)
        offset += serialLen

        // Skip signature algorithm
        guard bytes[offset] == 0x30 else { return nil }
        offset += 1
        let sigAlgLen = parseLength(bytes, offset: &offset)
        offset += sigAlgLen

        // Issuer is here
        guard bytes[offset] == 0x30 else { return nil }
        let issuerStart = offset
        offset += 1
        let issuerLen = parseLength(bytes, offset: &offset)
        let issuerTotalLen = 1 + lengthOfLength(issuerLen) + issuerLen

        return Array(bytes[issuerStart..<(issuerStart + issuerTotalLen)])
    }

    private func parseLength(_ bytes: [UInt8], offset: inout Int) -> Int {
        guard offset < bytes.count else { return 0 }
        let first = bytes[offset]
        offset += 1

        if first < 128 {
            return Int(first)
        }

        let numBytes = Int(first & 0x7F)
        var length = 0
        for _ in 0..<numBytes {
            guard offset < bytes.count else { return 0 }
            length = (length << 8) | Int(bytes[offset])
            offset += 1
        }
        return length
    }

    private func lengthOfLength(_ length: Int) -> Int {
        if length < 128 { return 1 }
        var len = length
        var bytes = 0
        while len > 0 {
            bytes += 1
            len >>= 8
        }
        return bytes + 1
    }

    private func signData(_ data: Data, with privateKey: SecKey) -> Data? {
        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256

        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            return nil
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
            return nil
        }

        return signature
    }

    // MARK: - TLS Options

    /// Creates TLS parameters for client-side connection (proxy to real server).
    func createClientTLSParameters(for hostname: String) -> NWParameters {
        let tlsOptions = NWProtocolTLS.Options()

        // Trust all certificates from real servers (we're the MITM)
        sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { _, trust, complete in
            // Accept all server certificates
            complete(true)
        }, .main)

        // Set SNI
        sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, hostname)

        let tcpOptions = NWProtocolTCP.Options()
        return NWParameters(tls: tlsOptions, tcp: tcpOptions)
    }

    /// Creates TLS parameters for server-side connection (app to proxy).
    func createServerTLSParameters(for hostname: String) -> NWParameters? {
        guard let (identity, _) = getCertificate(for: hostname) else {
            return nil
        }

        let tlsOptions = NWProtocolTLS.Options()

        // Set our identity (certificate + private key)
        sec_protocol_options_set_local_identity(tlsOptions.securityProtocolOptions, sec_identity_create(identity)!)

        let tcpOptions = NWProtocolTCP.Options()
        return NWParameters(tls: tlsOptions, tcp: tcpOptions)
    }
}
