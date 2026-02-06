import Foundation
import Security
import os.log

/// Generates X.509 certificates for TLS interception.
/// Creates a CA certificate for signing leaf certificates, and generates
/// per-host leaf certificates on demand.
public final class CertificateGenerator: Sendable {

    private let logger = Logger(subsystem: "com.wudan.iris", category: "CertificateGenerator")

    /// Default RSA key size for generated certificates
    public static let defaultKeySize = 2048

    /// CA certificate validity period (10 years)
    public static let caValidityDays: Double = 365 * 10

    /// Leaf certificate validity period (1 year)
    public static let leafValidityDays: Double = 365

    /// Organization name for generated certificates
    public static let organizationName = "Iris Proxy"

    /// CA common name
    public static let caCommonName = "Iris Root CA"

    public init() {}

    // MARK: - CA Certificate Generation

    /// Generates a new CA private key and self-signed certificate.
    /// - Parameter keySize: RSA key size in bits (default: 2048)
    /// - Returns: Tuple of (privateKey, certificate) as SecKey and SecCertificate
    /// - Throws: CertificateError if generation fails
    public func createCA(keySize: Int = defaultKeySize) throws -> (privateKey: SecKey, certificate: SecCertificate) {
        logger.info("Generating new CA certificate with \(keySize)-bit RSA key")

        // Generate RSA key pair
        let privateKey = try generateRSAKeyPair(keySize: keySize)

        // Create CA certificate
        let certificate = try createCACertificate(privateKey: privateKey)

        logger.info("Successfully generated CA certificate")
        return (privateKey, certificate)
    }

    /// Generates an RSA key pair.
    /// - Parameter keySize: Key size in bits
    /// - Returns: The private key (public key can be derived from it)
    /// - Throws: CertificateError if key generation fails
    private func generateRSAKeyPair(keySize: Int) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize,
            kSecAttrIsPermanent as String: false
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            logger.error("Failed to generate RSA key pair: \(errorMessage)")
            throw CertificateError.keyGenerationFailed(errorMessage)
        }

        return privateKey
    }

    /// Creates a self-signed CA certificate.
    /// - Parameter privateKey: The CA's private key
    /// - Returns: The CA certificate
    /// - Throws: CertificateError if certificate creation fails
    private func createCACertificate(privateKey: SecKey) throws -> SecCertificate {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw CertificateError.publicKeyExtractionFailed
        }

        // Build certificate data
        let now = Date()
        let notBefore = now.addingTimeInterval(-2 * 24 * 60 * 60) // 2 days ago
        let notAfter = now.addingTimeInterval(Self.caValidityDays * 24 * 60 * 60)

        let serialNumber = generateSerialNumber()

        // Create the certificate using a DER-encoded structure
        let certificateData = try buildCACertificateData(
            publicKey: publicKey,
            privateKey: privateKey,
            serialNumber: serialNumber,
            notBefore: notBefore,
            notAfter: notAfter,
            commonName: Self.caCommonName,
            organization: Self.organizationName
        )

        guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            throw CertificateError.certificateCreationFailed("Failed to create SecCertificate from data")
        }

        return certificate
    }

    // MARK: - Leaf Certificate Generation

    /// Generates a leaf certificate for a specific hostname, signed by the CA.
    /// - Parameters:
    ///   - hostname: The hostname for the certificate (used in CN and SAN)
    ///   - caPrivateKey: The CA's private key for signing
    ///   - caCertificate: The CA certificate (for issuer info)
    /// - Returns: Tuple of (privateKey, certificate) for the leaf
    /// - Throws: CertificateError if generation fails
    public func createLeafCertificate(
        hostname: String,
        caPrivateKey: SecKey,
        caCertificate: SecCertificate
    ) throws -> (privateKey: SecKey, certificate: SecCertificate) {
        logger.debug("Generating leaf certificate for hostname: \(hostname)")

        // Generate new key pair for the leaf certificate
        let leafPrivateKey = try generateRSAKeyPair(keySize: Self.defaultKeySize)

        guard let leafPublicKey = SecKeyCopyPublicKey(leafPrivateKey) else {
            throw CertificateError.publicKeyExtractionFailed
        }

        let now = Date()
        let notBefore = now.addingTimeInterval(-2 * 24 * 60 * 60)
        let notAfter = now.addingTimeInterval(Self.leafValidityDays * 24 * 60 * 60)

        let serialNumber = generateSerialNumber()

        let certificateData = try buildLeafCertificateData(
            publicKey: leafPublicKey,
            signingKey: caPrivateKey,
            caCertificate: caCertificate,
            serialNumber: serialNumber,
            notBefore: notBefore,
            notAfter: notAfter,
            hostname: hostname
        )

        guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            throw CertificateError.certificateCreationFailed("Failed to create leaf certificate")
        }

        logger.debug("Successfully generated leaf certificate for \(hostname)")
        return (leafPrivateKey, certificate)
    }

    // MARK: - Certificate Building (ASN.1 DER encoding)

    /// Builds the DER-encoded data for a CA certificate.
    private func buildCACertificateData(
        publicKey: SecKey,
        privateKey: SecKey,
        serialNumber: Data,
        notBefore: Date,
        notAfter: Date,
        commonName: String,
        organization: String
    ) throws -> Data {
        // Get public key data
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw CertificateError.publicKeyExtractionFailed
        }

        // Build the TBS (To Be Signed) certificate
        var tbsCertificate = Data()

        // Version (v3 = 2)
        tbsCertificate.append(contentsOf: buildExplicitTag(0, content: buildInteger(2)))

        // Serial number
        tbsCertificate.append(contentsOf: buildInteger(serialNumber))

        // Signature algorithm (SHA256 with RSA)
        tbsCertificate.append(contentsOf: buildSignatureAlgorithm())

        // Issuer (same as subject for CA)
        let issuerName = buildDistinguishedName(commonName: commonName, organization: organization)
        tbsCertificate.append(contentsOf: issuerName)

        // Validity
        tbsCertificate.append(contentsOf: buildValidity(notBefore: notBefore, notAfter: notAfter))

        // Subject
        tbsCertificate.append(contentsOf: issuerName)

        // Subject Public Key Info
        tbsCertificate.append(contentsOf: buildSubjectPublicKeyInfo(publicKeyData: publicKeyData))

        // Extensions (v3)
        let extensions = buildCAExtensions()
        tbsCertificate.append(contentsOf: buildExplicitTag(3, content: buildSequence(extensions)))

        // Wrap TBS in sequence
        let tbsSequence = buildSequence(tbsCertificate)

        // Sign the TBS certificate
        let signature = try signData(Data(tbsSequence), with: privateKey)

        // Build final certificate
        var certificate = Data()
        certificate.append(contentsOf: tbsSequence)
        certificate.append(contentsOf: buildSignatureAlgorithm())
        certificate.append(contentsOf: buildBitString(signature))

        return Data(buildSequence(certificate))
    }

    /// Builds the DER-encoded data for a leaf certificate.
    private func buildLeafCertificateData(
        publicKey: SecKey,
        signingKey: SecKey,
        caCertificate: SecCertificate,
        serialNumber: Data,
        notBefore: Date,
        notAfter: Date,
        hostname: String
    ) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw CertificateError.publicKeyExtractionFailed
        }

        // Extract issuer name from CA certificate
        let issuerName = try extractIssuerName(from: caCertificate)

        // Build TBS certificate
        var tbsCertificate = Data()

        // Version (v3 = 2)
        tbsCertificate.append(contentsOf: buildExplicitTag(0, content: buildInteger(2)))

        // Serial number
        tbsCertificate.append(contentsOf: buildInteger(serialNumber))

        // Signature algorithm
        tbsCertificate.append(contentsOf: buildSignatureAlgorithm())

        // Issuer (from CA)
        tbsCertificate.append(contentsOf: issuerName)

        // Validity
        tbsCertificate.append(contentsOf: buildValidity(notBefore: notBefore, notAfter: notAfter))

        // Subject (hostname as CN)
        let subjectName = buildDistinguishedName(commonName: hostname, organization: nil)
        tbsCertificate.append(contentsOf: subjectName)

        // Subject Public Key Info
        tbsCertificate.append(contentsOf: buildSubjectPublicKeyInfo(publicKeyData: publicKeyData))

        // Extensions
        let extensions = buildLeafExtensions(hostname: hostname)
        tbsCertificate.append(contentsOf: buildExplicitTag(3, content: buildSequence(extensions)))

        // Wrap TBS in sequence
        let tbsSequence = buildSequence(tbsCertificate)

        // Sign with CA private key
        let signature = try signData(Data(tbsSequence), with: signingKey)

        // Build final certificate
        var certificate = Data()
        certificate.append(contentsOf: tbsSequence)
        certificate.append(contentsOf: buildSignatureAlgorithm())
        certificate.append(contentsOf: buildBitString(signature))

        return Data(buildSequence(certificate))
    }

    // MARK: - ASN.1 DER Encoding Helpers

    /// Generates a random serial number.
    private func generateSerialNumber() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        // Ensure high bit is clear (positive integer)
        bytes[0] &= 0x7F
        return Data(bytes)
    }

    /// Builds a DER INTEGER from data.
    private func buildInteger(_ value: Int) -> [UInt8] {
        var result: [UInt8] = [0x02] // INTEGER tag

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
            // Add leading zero if high bit is set
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, at: 0)
            }
            result.append(contentsOf: encodeLength(bytes.count))
            result.append(contentsOf: bytes)
        }

        return result
    }

    /// Builds a DER INTEGER from data bytes.
    private func buildInteger(_ data: Data) -> [UInt8] {
        var result: [UInt8] = [0x02] // INTEGER tag
        var bytes = [UInt8](data)

        // Add leading zero if high bit is set
        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }

        result.append(contentsOf: encodeLength(bytes.count))
        result.append(contentsOf: bytes)
        return result
    }

    /// Builds a DER SEQUENCE.
    private func buildSequence(_ content: Data) -> [UInt8] {
        var result: [UInt8] = [0x30] // SEQUENCE tag
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    /// Builds a DER SEQUENCE from byte array.
    private func buildSequence(_ content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [0x30]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    /// Builds a DER BIT STRING.
    private func buildBitString(_ data: Data) -> [UInt8] {
        var result: [UInt8] = [0x03] // BIT STRING tag
        result.append(contentsOf: encodeLength(data.count + 1))
        result.append(0) // unused bits
        result.append(contentsOf: data)
        return result
    }

    /// Builds a DER OCTET STRING.
    private func buildOctetString(_ data: Data) -> [UInt8] {
        var result: [UInt8] = [0x04] // OCTET STRING tag
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    /// Builds a DER OBJECT IDENTIFIER.
    private func buildOID(_ oid: [UInt]) -> [UInt8] {
        var result: [UInt8] = [0x06] // OID tag

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

    /// Encodes a single OID component using variable-length encoding.
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

    /// Builds a UTF8String.
    private func buildUTF8String(_ string: String) -> [UInt8] {
        let data = Data(string.utf8)
        var result: [UInt8] = [0x0C] // UTF8String tag
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    /// Builds a PrintableString.
    private func buildPrintableString(_ string: String) -> [UInt8] {
        let data = Data(string.utf8)
        var result: [UInt8] = [0x13] // PrintableString tag
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    /// Builds a UTCTime.
    private func buildUTCTime(_ date: Date) -> [UInt8] {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        formatter.timeZone = TimeZone(identifier: "UTC")
        let dateString = formatter.string(from: date)
        let data = Data(dateString.utf8)

        var result: [UInt8] = [0x17] // UTCTime tag
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    /// Builds a GeneralizedTime.
    private func buildGeneralizedTime(_ date: Date) -> [UInt8] {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        formatter.timeZone = TimeZone(identifier: "UTC")
        let dateString = formatter.string(from: date)
        let data = Data(dateString.utf8)

        var result: [UInt8] = [0x18] // GeneralizedTime tag
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    /// Builds an explicit context tag.
    private func buildExplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [UInt8(0xA0 + tag)]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    /// Builds an implicit context tag.
    private func buildImplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [UInt8(0x80 + tag)]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    /// Builds a BOOLEAN.
    private func buildBoolean(_ value: Bool) -> [UInt8] {
        return [0x01, 0x01, value ? 0xFF : 0x00]
    }

    /// Encodes a length in DER format.
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

    // MARK: - Certificate Components

    /// Builds the signature algorithm identifier (SHA256 with RSA).
    private func buildSignatureAlgorithm() -> [UInt8] {
        // OID for sha256WithRSAEncryption: 1.2.840.113549.1.1.11
        let oid = buildOID([1, 2, 840, 113549, 1, 1, 11])
        let null: [UInt8] = [0x05, 0x00] // NULL

        var content = Data()
        content.append(contentsOf: oid)
        content.append(contentsOf: null)

        return buildSequence(content)
    }

    /// Builds a distinguished name.
    private func buildDistinguishedName(commonName: String, organization: String?) -> [UInt8] {
        var rdnSequence = Data()

        // Common Name
        let cnOID = buildOID([2, 5, 4, 3]) // id-at-commonName
        let cnValue = buildUTF8String(commonName)
        var cnAttrValue = Data()
        cnAttrValue.append(contentsOf: cnOID)
        cnAttrValue.append(contentsOf: cnValue)
        let cnSet = buildSet(buildSequence(cnAttrValue))
        rdnSequence.append(contentsOf: cnSet)

        // Organization (optional)
        if let org = organization {
            let oOID = buildOID([2, 5, 4, 10]) // id-at-organizationName
            let oValue = buildUTF8String(org)
            var oAttrValue = Data()
            oAttrValue.append(contentsOf: oOID)
            oAttrValue.append(contentsOf: oValue)
            let oSet = buildSet(buildSequence(oAttrValue))
            rdnSequence.append(contentsOf: oSet)
        }

        return buildSequence(rdnSequence)
    }

    /// Builds a SET.
    private func buildSet(_ content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [0x31] // SET tag
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    /// Builds the validity period.
    private func buildValidity(notBefore: Date, notAfter: Date) -> [UInt8] {
        var content = Data()
        content.append(contentsOf: buildUTCTime(notBefore))
        content.append(contentsOf: buildUTCTime(notAfter))
        return buildSequence(content)
    }

    /// Builds the SubjectPublicKeyInfo structure.
    private func buildSubjectPublicKeyInfo(publicKeyData: Data) -> [UInt8] {
        // Algorithm identifier for RSA
        let rsaOID = buildOID([1, 2, 840, 113549, 1, 1, 1]) // rsaEncryption
        let null: [UInt8] = [0x05, 0x00]
        var algorithm = Data()
        algorithm.append(contentsOf: rsaOID)
        algorithm.append(contentsOf: null)
        let algorithmSequence = buildSequence(algorithm)

        // Public key as bit string - need to wrap in SEQUENCE first
        let publicKeySequence = buildSequence(publicKeyData)
        let publicKeyBitString = buildBitString(Data(publicKeySequence))

        var content = Data()
        content.append(contentsOf: algorithmSequence)
        content.append(contentsOf: publicKeyBitString)

        return buildSequence(content)
    }

    /// Builds CA certificate extensions.
    private func buildCAExtensions() -> Data {
        var extensions = Data()

        // Basic Constraints (CA: true, critical)
        let basicConstraintsOID = buildOID([2, 5, 29, 19])
        var bcValue = Data()
        bcValue.append(contentsOf: buildBoolean(true)) // CA: true
        let bcValueSequence = buildSequence(bcValue)
        let bcOctetString = buildOctetString(Data(bcValueSequence))

        var bcExtension = Data()
        bcExtension.append(contentsOf: basicConstraintsOID)
        bcExtension.append(contentsOf: buildBoolean(true)) // critical
        bcExtension.append(contentsOf: bcOctetString)
        extensions.append(contentsOf: buildSequence(bcExtension))

        // Key Usage (keyCertSign, cRLSign, critical)
        let keyUsageOID = buildOID([2, 5, 29, 15])
        // keyCertSign (bit 5) | cRLSign (bit 6) = 0x06
        let keyUsageBits: [UInt8] = [0x03, 0x02, 0x01, 0x06]
        let kuOctetString = buildOctetString(Data(keyUsageBits))

        var kuExtension = Data()
        kuExtension.append(contentsOf: keyUsageOID)
        kuExtension.append(contentsOf: buildBoolean(true)) // critical
        kuExtension.append(contentsOf: kuOctetString)
        extensions.append(contentsOf: buildSequence(kuExtension))

        return extensions
    }

    /// Builds leaf certificate extensions.
    private func buildLeafExtensions(hostname: String) -> Data {
        var extensions = Data()

        // Basic Constraints (CA: false)
        let basicConstraintsOID = buildOID([2, 5, 29, 19])
        let bcValueSequence = buildSequence(Data()) // empty = CA: false
        let bcOctetString = buildOctetString(Data(bcValueSequence))

        var bcExtension = Data()
        bcExtension.append(contentsOf: basicConstraintsOID)
        bcExtension.append(contentsOf: bcOctetString)
        extensions.append(contentsOf: buildSequence(bcExtension))

        // Extended Key Usage (serverAuth)
        let extKeyUsageOID = buildOID([2, 5, 29, 37])
        let serverAuthOID = buildOID([1, 3, 6, 1, 5, 5, 7, 3, 1])
        let ekuValueSequence = buildSequence(serverAuthOID)
        let ekuOctetString = buildOctetString(Data(ekuValueSequence))

        var ekuExtension = Data()
        ekuExtension.append(contentsOf: extKeyUsageOID)
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

    /// Extracts the issuer name from a CA certificate.
    private func extractIssuerName(from certificate: SecCertificate) throws -> [UInt8] {
        guard let certData = SecCertificateCopyData(certificate) as Data? else {
            throw CertificateError.certificateParsingFailed("Failed to get certificate data")
        }

        // Parse the certificate to find the subject name (which is our issuer)
        // This is a simplified parser - we look for the subject in the TBS certificate
        let bytes = [UInt8](certData)

        // Skip certificate sequence header
        guard bytes.count > 4, bytes[0] == 0x30 else {
            throw CertificateError.certificateParsingFailed("Invalid certificate format")
        }

        var offset = 1
        let (_, seqLen) = try parseLength(bytes, offset: offset)
        offset += seqLen

        // Skip TBS certificate sequence header
        guard bytes[offset] == 0x30 else {
            throw CertificateError.certificateParsingFailed("Invalid TBS certificate")
        }
        offset += 1
        let (_, tbsLen) = try parseLength(bytes, offset: offset)
        offset += tbsLen

        // Skip version (explicit tag 0)
        if bytes[offset] == 0xA0 {
            offset += 1
            let (_, vLen) = try parseLength(bytes, offset: offset)
            offset += vLen
            let (vContentLen, _) = try parseLength(bytes, offset: offset)
            offset += vContentLen
        }

        // Skip serial number
        guard bytes[offset] == 0x02 else {
            throw CertificateError.certificateParsingFailed("Expected serial number")
        }
        offset += 1
        let (serialLen, serialLenSize) = try parseLength(bytes, offset: offset)
        offset += serialLenSize + serialLen

        // Skip signature algorithm
        guard bytes[offset] == 0x30 else {
            throw CertificateError.certificateParsingFailed("Expected signature algorithm")
        }
        offset += 1
        let (sigAlgLen, sigAlgLenSize) = try parseLength(bytes, offset: offset)
        offset += sigAlgLenSize + sigAlgLen

        // Issuer is here - extract the whole SEQUENCE
        guard bytes[offset] == 0x30 else {
            throw CertificateError.certificateParsingFailed("Expected issuer")
        }
        let issuerStart = offset
        offset += 1
        let (issuerLen, issuerLenSize) = try parseLength(bytes, offset: offset)
        let issuerTotalLen = 1 + issuerLenSize + issuerLen

        return Array(bytes[issuerStart..<(issuerStart + issuerTotalLen)])
    }

    /// Parses a DER length field.
    private func parseLength(_ bytes: [UInt8], offset: Int) throws -> (length: Int, bytesConsumed: Int) {
        guard offset < bytes.count else {
            throw CertificateError.certificateParsingFailed("Unexpected end of data")
        }

        let first = bytes[offset]
        if first < 128 {
            return (Int(first), 1)
        }

        let numBytes = Int(first & 0x7F)
        guard offset + numBytes < bytes.count else {
            throw CertificateError.certificateParsingFailed("Invalid length encoding")
        }

        var length = 0
        for i in 0..<numBytes {
            length = (length << 8) | Int(bytes[offset + 1 + i])
        }

        return (length, numBytes + 1)
    }

    // MARK: - Signing

    /// Signs data using the private key.
    private func signData(_ data: Data, with privateKey: SecKey) throws -> Data {
        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256

        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw CertificateError.signingFailed("Algorithm not supported")
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw CertificateError.signingFailed(errorMessage)
        }

        return signature
    }

    // MARK: - Export

    /// Exports a certificate as PEM-encoded data.
    public func exportCertificateAsPEM(_ certificate: SecCertificate) -> String {
        guard let data = SecCertificateCopyData(certificate) as Data? else {
            return ""
        }

        let base64 = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE-----\n\(base64)\n-----END CERTIFICATE-----\n"
    }

    /// Exports a private key as PEM-encoded data.
    public func exportPrivateKeyAsPEM(_ privateKey: SecKey) -> String? {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            return nil
        }

        let base64 = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN RSA PRIVATE KEY-----\n\(base64)\n-----END RSA PRIVATE KEY-----\n"
    }
}

// MARK: - Errors

/// Errors that can occur during certificate operations.
public enum CertificateError: Error, LocalizedError {
    case keyGenerationFailed(String)
    case publicKeyExtractionFailed
    case certificateCreationFailed(String)
    case certificateParsingFailed(String)
    case signingFailed(String)
    case keychainError(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .keyGenerationFailed(let msg):
            return "Key generation failed: \(msg)"
        case .publicKeyExtractionFailed:
            return "Failed to extract public key"
        case .certificateCreationFailed(let msg):
            return "Certificate creation failed: \(msg)"
        case .certificateParsingFailed(let msg):
            return "Certificate parsing failed: \(msg)"
        case .signingFailed(let msg):
            return "Signing failed: \(msg)"
        case .keychainError(let status):
            return "Keychain error: \(status)"
        }
    }
}
