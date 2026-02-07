import Foundation
import Security
import os.log

/// Generates X.509 certificates for TLS interception.
/// Creates a CA certificate for signing leaf certificates, and generates
/// per-host leaf certificates on demand.
public final class CertificateGenerator: Sendable {

    let logger = Logger(subsystem: "com.wudan.iris", category: "CertificateGenerator")

    public static let defaultKeySize = 2048
    public static let caValidityDays: Double = 365 * 10
    public static let leafValidityDays: Double = 365
    public static let organizationName = "Iris Proxy"
    public static let caCommonName = "Iris Root CA"

    public init() {}

    // MARK: - CA Certificate Generation

    public func createCA(keySize: Int = defaultKeySize) throws -> (privateKey: SecKey, certificate: SecCertificate) {
        logger.info("Generating new CA certificate with \(keySize)-bit RSA key")
        let privateKey = try generateRSAKeyPair(keySize: keySize)
        let certificate = try createCACertificate(privateKey: privateKey)
        logger.info("Successfully generated CA certificate")
        return (privateKey, certificate)
    }

    func generateRSAKeyPair(keySize: Int) throws -> SecKey {
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

    func createCACertificate(privateKey: SecKey) throws -> SecCertificate {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw CertificateError.publicKeyExtractionFailed
        }

        let now = Date()
        let notBefore = now.addingTimeInterval(-2 * 24 * 60 * 60)
        let notAfter = now.addingTimeInterval(Self.caValidityDays * 24 * 60 * 60)
        let serialNumber = generateSerialNumber()

        let certificateData = try buildCACertificateData(
            publicKey: publicKey, privateKey: privateKey,
            serialNumber: serialNumber,
            notBefore: notBefore, notAfter: notAfter,
            commonName: Self.caCommonName, organization: Self.organizationName
        )

        guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            throw CertificateError.certificateCreationFailed("Failed to create SecCertificate from data")
        }
        return certificate
    }

    // MARK: - Leaf Certificate Generation

    public func createLeafCertificate(
        hostname: String, caPrivateKey: SecKey, caCertificate: SecCertificate
    ) throws -> (privateKey: SecKey, certificate: SecCertificate) {
        logger.debug("Generating leaf certificate for hostname: \(hostname)")

        let leafPrivateKey = try generateRSAKeyPair(keySize: Self.defaultKeySize)
        guard let leafPublicKey = SecKeyCopyPublicKey(leafPrivateKey) else {
            throw CertificateError.publicKeyExtractionFailed
        }

        let now = Date()
        let notBefore = now.addingTimeInterval(-2 * 24 * 60 * 60)
        let notAfter = now.addingTimeInterval(Self.leafValidityDays * 24 * 60 * 60)
        let serialNumber = generateSerialNumber()

        let certificateData = try buildLeafCertificateData(
            publicKey: leafPublicKey, signingKey: caPrivateKey,
            caCertificate: caCertificate, serialNumber: serialNumber,
            notBefore: notBefore, notAfter: notAfter, hostname: hostname
        )

        guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            throw CertificateError.certificateCreationFailed("Failed to create leaf certificate")
        }

        logger.debug("Successfully generated leaf certificate for \(hostname)")
        return (leafPrivateKey, certificate)
    }

    // MARK: - Certificate Building

    func buildCACertificateData(
        publicKey: SecKey, privateKey: SecKey,
        serialNumber: Data, notBefore: Date, notAfter: Date,
        commonName: String, organization: String
    ) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw CertificateError.publicKeyExtractionFailed
        }

        var tbsCertificate = Data()
        tbsCertificate.append(contentsOf: buildExplicitTag(0, content: buildInteger(2)))
        tbsCertificate.append(contentsOf: buildInteger(serialNumber))
        tbsCertificate.append(contentsOf: buildSignatureAlgorithm())

        let issuerName = buildDistinguishedName(commonName: commonName, organization: organization)
        tbsCertificate.append(contentsOf: issuerName)
        tbsCertificate.append(contentsOf: buildValidity(notBefore: notBefore, notAfter: notAfter))
        tbsCertificate.append(contentsOf: issuerName)
        tbsCertificate.append(contentsOf: buildSubjectPublicKeyInfo(publicKeyData: publicKeyData))

        let extensions = buildCAExtensions()
        tbsCertificate.append(contentsOf: buildExplicitTag(3, content: buildSequence(extensions)))

        let tbsSequence = buildSequence(tbsCertificate)
        let signature = try signData(Data(tbsSequence), with: privateKey)

        var certificate = Data()
        certificate.append(contentsOf: tbsSequence)
        certificate.append(contentsOf: buildSignatureAlgorithm())
        certificate.append(contentsOf: buildBitString(signature))

        return Data(buildSequence(certificate))
    }

    func buildLeafCertificateData(
        publicKey: SecKey, signingKey: SecKey,
        caCertificate: SecCertificate, serialNumber: Data,
        notBefore: Date, notAfter: Date, hostname: String
    ) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw CertificateError.publicKeyExtractionFailed
        }

        let issuerName = try extractIssuerName(from: caCertificate)

        var tbsCertificate = Data()
        tbsCertificate.append(contentsOf: buildExplicitTag(0, content: buildInteger(2)))
        tbsCertificate.append(contentsOf: buildInteger(serialNumber))
        tbsCertificate.append(contentsOf: buildSignatureAlgorithm())
        tbsCertificate.append(contentsOf: issuerName)
        tbsCertificate.append(contentsOf: buildValidity(notBefore: notBefore, notAfter: notAfter))

        let subjectName = buildDistinguishedName(commonName: hostname, organization: nil)
        tbsCertificate.append(contentsOf: subjectName)
        tbsCertificate.append(contentsOf: buildSubjectPublicKeyInfo(publicKeyData: publicKeyData))

        let extensions = buildLeafExtensions(hostname: hostname)
        tbsCertificate.append(contentsOf: buildExplicitTag(3, content: buildSequence(extensions)))

        let tbsSequence = buildSequence(tbsCertificate)
        let signature = try signData(Data(tbsSequence), with: signingKey)

        var certificate = Data()
        certificate.append(contentsOf: tbsSequence)
        certificate.append(contentsOf: buildSignatureAlgorithm())
        certificate.append(contentsOf: buildBitString(signature))

        return Data(buildSequence(certificate))
    }
}
