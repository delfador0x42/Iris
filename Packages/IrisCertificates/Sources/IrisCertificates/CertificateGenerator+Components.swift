import Foundation
import Security

/// Certificate component builders: extensions, DN, SPKI, signing, parsing, export.
extension CertificateGenerator {

    func buildSignatureAlgorithm() -> [UInt8] {
        let oid = buildOID([1, 2, 840, 113549, 1, 1, 11])
        let null: [UInt8] = [0x05, 0x00]
        var content = Data()
        content.append(contentsOf: oid)
        content.append(contentsOf: null)
        return buildSequence(content)
    }

    func buildDistinguishedName(commonName: String, organization: String?) -> [UInt8] {
        var rdnSequence = Data()

        let cnOID = buildOID([2, 5, 4, 3])
        let cnValue = buildUTF8String(commonName)
        var cnAttrValue = Data()
        cnAttrValue.append(contentsOf: cnOID)
        cnAttrValue.append(contentsOf: cnValue)
        rdnSequence.append(contentsOf: buildSet(buildSequence(cnAttrValue)))

        if let org = organization {
            let oOID = buildOID([2, 5, 4, 10])
            let oValue = buildUTF8String(org)
            var oAttrValue = Data()
            oAttrValue.append(contentsOf: oOID)
            oAttrValue.append(contentsOf: oValue)
            rdnSequence.append(contentsOf: buildSet(buildSequence(oAttrValue)))
        }

        return buildSequence(rdnSequence)
    }

    func buildSet(_ content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [0x31]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    func buildValidity(notBefore: Date, notAfter: Date) -> [UInt8] {
        var content = Data()
        content.append(contentsOf: buildUTCTime(notBefore))
        content.append(contentsOf: buildUTCTime(notAfter))
        return buildSequence(content)
    }

    func buildSubjectPublicKeyInfo(publicKeyData: Data) -> [UInt8] {
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

    // MARK: - CA Extensions

    func buildCAExtensions() -> Data {
        var extensions = Data()

        // Basic Constraints (CA: true, critical)
        let bcOID = buildOID([2, 5, 29, 19])
        var bcValue = Data()
        bcValue.append(contentsOf: buildBoolean(true))
        let bcOctetString = buildOctetString(Data(buildSequence(bcValue)))
        var bcExtension = Data()
        bcExtension.append(contentsOf: bcOID)
        bcExtension.append(contentsOf: buildBoolean(true))
        bcExtension.append(contentsOf: bcOctetString)
        extensions.append(contentsOf: buildSequence(bcExtension))

        // Key Usage (keyCertSign, cRLSign, critical)
        let kuOID = buildOID([2, 5, 29, 15])
        let keyUsageBits: [UInt8] = [0x03, 0x02, 0x01, 0x06]
        let kuOctetString = buildOctetString(Data(keyUsageBits))
        var kuExtension = Data()
        kuExtension.append(contentsOf: kuOID)
        kuExtension.append(contentsOf: buildBoolean(true))
        kuExtension.append(contentsOf: kuOctetString)
        extensions.append(contentsOf: buildSequence(kuExtension))

        return extensions
    }

    // MARK: - Leaf Extensions

    func buildLeafExtensions(hostname: String) -> Data {
        var extensions = Data()

        // Basic Constraints (CA: false, critical)
        let bcOID = buildOID([2, 5, 29, 19])
        var bcExtension = Data()
        bcExtension.append(contentsOf: bcOID)
        bcExtension.append(contentsOf: buildBoolean(true))
        bcExtension.append(contentsOf: buildOctetString(Data(buildSequence(Data()))))
        extensions.append(contentsOf: buildSequence(bcExtension))

        // Key Usage (digitalSignature + keyEncipherment, critical)
        let kuOID = buildOID([2, 5, 29, 15])
        let kuBitString: [UInt8] = [0x03, 0x03, 0x05, 0xA0, 0x00]
        var kuExtension = Data()
        kuExtension.append(contentsOf: kuOID)
        kuExtension.append(contentsOf: buildBoolean(true))
        kuExtension.append(contentsOf: buildOctetString(Data(kuBitString)))
        extensions.append(contentsOf: buildSequence(kuExtension))

        // Extended Key Usage (serverAuth)
        let ekuOID = buildOID([2, 5, 29, 37])
        let serverAuthOID = buildOID([1, 3, 6, 1, 5, 5, 7, 3, 1])
        let ekuOctetString = buildOctetString(Data(buildSequence(serverAuthOID)))
        var ekuExtension = Data()
        ekuExtension.append(contentsOf: ekuOID)
        ekuExtension.append(contentsOf: ekuOctetString)
        extensions.append(contentsOf: buildSequence(ekuExtension))

        // Subject Alternative Name (DNS or IP)
        let sanOID = buildOID([2, 5, 29, 17])
        var sanValue: [UInt8]
        if let ipBytes = parseIPAddress(hostname) {
            sanValue = buildImplicitTag(7, content: ipBytes)
        } else {
            sanValue = buildImplicitTag(2, content: [UInt8](hostname.utf8))
        }
        let sanOctetString = buildOctetString(Data(buildSequence(sanValue)))
        var sanExtension = Data()
        sanExtension.append(contentsOf: sanOID)
        sanExtension.append(contentsOf: sanOctetString)
        extensions.append(contentsOf: buildSequence(sanExtension))

        return extensions
    }

    private func parseIPAddress(_ host: String) -> [UInt8]? {
        var addr4 = in_addr()
        if inet_pton(AF_INET, host, &addr4) == 1 {
            return withUnsafeBytes(of: &addr4) { Array($0) }
        }
        var addr6 = in6_addr()
        if inet_pton(AF_INET6, host, &addr6) == 1 {
            return withUnsafeBytes(of: &addr6) { Array($0) }
        }
        return nil
    }

    // MARK: - DER Parsing

    func extractIssuerName(from certificate: SecCertificate) throws -> [UInt8] {
        guard let certData = SecCertificateCopyData(certificate) as Data? else {
            throw CertificateError.certificateParsingFailed("Failed to get certificate data")
        }

        let bytes = [UInt8](certData)
        guard bytes.count > 4, bytes[0] == 0x30 else {
            throw CertificateError.certificateParsingFailed("Invalid certificate format")
        }

        var offset = 1
        let (_, seqLen) = try parseLength(bytes, offset: offset)
        offset += seqLen

        guard bytes[offset] == 0x30 else {
            throw CertificateError.certificateParsingFailed("Invalid TBS certificate")
        }
        offset += 1
        let (_, tbsLen) = try parseLength(bytes, offset: offset)
        offset += tbsLen

        if bytes[offset] == 0xA0 {
            offset += 1
            let (_, vLen) = try parseLength(bytes, offset: offset)
            offset += vLen
            let (vContentLen, _) = try parseLength(bytes, offset: offset)
            offset += vContentLen
        }

        guard bytes[offset] == 0x02 else {
            throw CertificateError.certificateParsingFailed("Expected serial number")
        }
        offset += 1
        let (serialLen, serialLenSize) = try parseLength(bytes, offset: offset)
        offset += serialLenSize + serialLen

        guard bytes[offset] == 0x30 else {
            throw CertificateError.certificateParsingFailed("Expected signature algorithm")
        }
        offset += 1
        let (sigAlgLen, sigAlgLenSize) = try parseLength(bytes, offset: offset)
        offset += sigAlgLenSize + sigAlgLen

        guard bytes[offset] == 0x30 else {
            throw CertificateError.certificateParsingFailed("Expected issuer")
        }
        let issuerStart = offset
        offset += 1
        let (issuerLen, issuerLenSize) = try parseLength(bytes, offset: offset)
        let issuerTotalLen = 1 + issuerLenSize + issuerLen

        return Array(bytes[issuerStart..<(issuerStart + issuerTotalLen)])
    }

    func parseLength(_ bytes: [UInt8], offset: Int) throws -> (length: Int, bytesConsumed: Int) {
        guard offset < bytes.count else {
            throw CertificateError.certificateParsingFailed("Unexpected end of data")
        }
        let first = bytes[offset]
        if first < 128 { return (Int(first), 1) }
        let numBytes = Int(first & 0x7F)
        guard offset + 1 + numBytes <= bytes.count else {
            throw CertificateError.certificateParsingFailed("Invalid length encoding")
        }
        var length = 0
        for i in 0..<numBytes { length = (length << 8) | Int(bytes[offset + 1 + i]) }
        return (length, numBytes + 1)
    }

    // MARK: - Signing

    func signData(_ data: Data, with privateKey: SecKey) throws -> Data {
        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw CertificateError.signingFailed("Algorithm not supported")
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
            throw CertificateError.signingFailed(error?.takeRetainedValue().localizedDescription ?? "Unknown error")
        }
        return signature
    }

    // MARK: - Export

    public func exportCertificateAsPEM(_ certificate: SecCertificate) -> String {
        guard let data = SecCertificateCopyData(certificate) as Data? else { return "" }
        let base64 = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE-----\n\(base64)\n-----END CERTIFICATE-----\n"
    }

    public func exportPrivateKeyAsPEM(_ privateKey: SecKey) -> String? {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else { return nil }
        let base64 = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN RSA PRIVATE KEY-----\n\(base64)\n-----END RSA PRIVATE KEY-----\n"
    }
}
