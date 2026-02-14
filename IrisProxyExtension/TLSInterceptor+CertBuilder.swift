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
  func generateCertificate(for hostname: String) -> (
    identity: SecIdentity, certificate: SecCertificate
  )? {
    // Snapshot CA under lock — both fields must be read atomically
    caLock.lock()
    let caKey = caPrivateKey
    let caCert = caCertificate
    caLock.unlock()

    guard let caPrivateKey = caKey, let caCertificate = caCert else {
      logger.error("Cannot generate certificate - CA not available")
      return nil
    }

    logger.debug("Generating certificate for \(hostname)")

    let keyAttributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeySizeInBits as String: 2048,
      kSecAttrIsPermanent as String: false,
    ]

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &error) else {
      logger.error(
        "Failed to generate key pair: \(error?.takeRetainedValue().localizedDescription ?? "unknown")"
      )
      return nil
    }

    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      logger.error("Failed to extract public key")
      return nil
    }

    guard
      let certificateData = buildLeafCertificate(
        hostname: hostname, publicKey: publicKey,
        caPrivateKey: caPrivateKey, caCertificate: caCertificate
      )
    else {
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
  ///
  /// Uses SecIdentityCreate (private API) wrapped in ObjC @try/@catch.
  /// SecIdentityCreate throws NSException → SIGABRT in system extensions.
  /// The ObjC wrapper catches the exception so the process survives.
  /// If the identity is created before the exception, we keep it.
  func createIdentity(privateKey: SecKey, certificate: SecCertificate) -> SecIdentity? {
    var exceptionReason: NSString?
    let identity = TrySecIdentityCreate(certificate, privateKey, &exceptionReason)

    if let reason = exceptionReason {
      logger.error("SecIdentityCreate threw exception: \(reason)")
    }

    if let identity {
      logger.debug("SecIdentityCreate succeeded")
      return identity
    }

    logger.error("SecIdentityCreate failed — identity is nil")
    return nil
  }

  /// Builds a leaf certificate for a hostname.
  func buildLeafCertificate(
    hostname: String, publicKey: SecKey,
    caPrivateKey: SecKey, caCertificate: SecCertificate
  ) -> Data? {
    var error: Unmanaged<CFError>?
    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      return nil
    }

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
