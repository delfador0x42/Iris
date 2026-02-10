//
//  TLSInterceptor+CertBuilder.swift
//  IrisProxyExtension
//
//  Certificate generation and identity creation for TLS MITM.
//

import Foundation
import Security
import os.log

extension TLSInterceptor {

    /// Generates a new certificate for a hostname.
    func generateCertificate(for hostname: String) -> (identity: SecIdentity, certificate: SecCertificate)? {
        guard let caPrivateKey = caPrivateKey,
              let caCertificate = caCertificate else {
            logger.error("Cannot generate certificate - CA not available")
            return nil
        }

        logger.debug("Generating certificate for \(hostname)")

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

        guard let certificateData = buildLeafCertificate(
            hostname: hostname, publicKey: publicKey,
            caPrivateKey: caPrivateKey, caCertificate: caCertificate
        ) else {
            logger.error("Failed to build certificate")
            return nil
        }

        guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            logger.error("Failed to create SecCertificate")
            return nil
        }

        guard let identity = createIdentity(privateKey: privateKey, certificate: certificate) else {
            logger.error("Failed to create identity")
            return nil
        }

        logger.debug("Successfully generated certificate for \(hostname)")
        return (identity, certificate)
    }

    /// Creates a SecIdentity from a private key and certificate.
    func createIdentity(privateKey: SecKey, certificate: SecCertificate) -> SecIdentity? {
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

        let addCertQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        status = SecItemAdd(addCertQuery as CFDictionary, nil)
        if status != errSecSuccess && status != errSecDuplicateItem {
            SecItemDelete(addKeyQuery as CFDictionary)
            logger.error("Failed to add certificate to keychain: \(status)")
            return nil
        }

        let identityQuery: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrApplicationTag as String: keyTag.data(using: .utf8)!,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var identityRef: CFTypeRef?
        status = SecItemCopyMatching(identityQuery as CFDictionary, &identityRef)

        SecItemDelete(addKeyQuery as CFDictionary)
        SecItemDelete(addCertQuery as CFDictionary)

        if status == errSecSuccess, let ref = identityRef,
           CFGetTypeID(ref) == SecIdentityGetTypeID() {
            return (ref as! SecIdentity)
        }
        return nil
    }

    /// Builds a leaf certificate for a hostname.
    func buildLeafCertificate(
        hostname: String, publicKey: SecKey,
        caPrivateKey: SecKey, caCertificate: SecCertificate
    ) -> Data? {
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else { return nil }

        let now = Date()
        let notBefore = now.addingTimeInterval(-2 * 24 * 60 * 60)
        let notAfter = now.addingTimeInterval(365 * 24 * 60 * 60)
        let serialNumber = generateSerialNumber()

        guard let issuerName = extractSubjectName(from: caCertificate) else { return nil }

        var tbsCertificate = Data()
        tbsCertificate.append(contentsOf: buildExplicitTag(0, content: buildInteger(2)))
        tbsCertificate.append(contentsOf: buildInteger(serialNumber))
        tbsCertificate.append(contentsOf: buildSignatureAlgorithm())
        tbsCertificate.append(contentsOf: issuerName)
        tbsCertificate.append(contentsOf: buildValidity(notBefore: notBefore, notAfter: notAfter))
        tbsCertificate.append(contentsOf: buildDistinguishedName(commonName: hostname))
        tbsCertificate.append(contentsOf: buildSubjectPublicKeyInfo(publicKeyData: publicKeyData))

        let extensions = buildLeafExtensions(hostname: hostname)
        tbsCertificate.append(contentsOf: buildExplicitTag(3, content: buildSequence(extensions)))

        let tbsSequence = buildSequence(tbsCertificate)

        guard let signature = signData(Data(tbsSequence), with: caPrivateKey) else { return nil }

        var certificate = Data()
        certificate.append(contentsOf: tbsSequence)
        certificate.append(contentsOf: buildSignatureAlgorithm())
        certificate.append(contentsOf: buildBitString(signature))

        return Data(buildSequence(certificate))
    }
}
