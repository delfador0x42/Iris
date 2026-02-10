//
//  TLSInterceptor+ASN1.swift
//  IrisProxyExtension
//
//  ASN.1 DER encoding helpers for certificate building.
//

import Foundation
import Security

extension TLSInterceptor {

    func generateSerialNumber() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            for i in stride(from: 0, to: bytes.count, by: 4) {
                var r = arc4random()
                withUnsafeBytes(of: &r) { src in
                    for j in 0..<min(4, bytes.count - i) { bytes[i + j] = src[j] }
                }
            }
        }
        bytes[0] &= 0x7F
        return Data(bytes)
    }

    func buildInteger(_ value: Int) -> [UInt8] {
        var result: [UInt8] = [0x02]
        if value == 0 {
            result.append(1); result.append(0)
        } else {
            var bytes: [UInt8] = []
            var v = value
            while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
            if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
            result.append(contentsOf: encodeLength(bytes.count))
            result.append(contentsOf: bytes)
        }
        return result
    }

    func buildInteger(_ data: Data) -> [UInt8] {
        var result: [UInt8] = [0x02]
        var bytes = [UInt8](data)
        if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
        result.append(contentsOf: encodeLength(bytes.count))
        result.append(contentsOf: bytes)
        return result
    }

    func buildSequence(_ content: Data) -> [UInt8] {
        var result: [UInt8] = [0x30]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    func buildSequence(_ content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [0x30]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    func buildBitString(_ data: Data) -> [UInt8] {
        var result: [UInt8] = [0x03]
        result.append(contentsOf: encodeLength(data.count + 1))
        result.append(0)
        result.append(contentsOf: data)
        return result
    }

    func buildOctetString(_ data: Data) -> [UInt8] {
        var result: [UInt8] = [0x04]
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    func buildOID(_ oid: [UInt]) -> [UInt8] {
        var result: [UInt8] = [0x06]
        var content: [UInt8] = []
        if oid.count >= 2 {
            content.append(UInt8(oid[0] * 40 + oid[1]))
            for i in 2..<oid.count { content.append(contentsOf: encodeOIDComponent(oid[i])) }
        }
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    func encodeOIDComponent(_ value: UInt) -> [UInt8] {
        if value < 128 { return [UInt8(value)] }
        var bytes: [UInt8] = []
        var v = value
        while v > 0 {
            bytes.insert(UInt8(v & 0x7F) | (bytes.isEmpty ? 0 : 0x80), at: 0)
            v >>= 7
        }
        return bytes
    }

    func buildUTF8String(_ string: String) -> [UInt8] {
        let data = Data(string.utf8)
        var result: [UInt8] = [0x0C]
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    func buildUTCTime(_ date: Date) -> [UInt8] {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        formatter.timeZone = TimeZone(identifier: "UTC")
        let data = Data(formatter.string(from: date).utf8)
        var result: [UInt8] = [0x17]
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    func buildExplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [UInt8(0xA0 + tag)]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    func buildImplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [UInt8(0x80 + tag)]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    func encodeLength(_ length: Int) -> [UInt8] {
        if length < 128 { return [UInt8(length)] }
        var bytes: [UInt8] = []
        var len = length
        while len > 0 { bytes.insert(UInt8(len & 0xFF), at: 0); len >>= 8 }
        return [UInt8(0x80 + bytes.count)] + bytes
    }

    func buildSignatureAlgorithm() -> [UInt8] {
        let oid = buildOID([1, 2, 840, 113549, 1, 1, 11])
        let null: [UInt8] = [0x05, 0x00]
        var content = Data()
        content.append(contentsOf: oid)
        content.append(contentsOf: null)
        return buildSequence(content)
    }

    func buildDistinguishedName(commonName: String) -> [UInt8] {
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

    func buildLeafExtensions(hostname: String) -> Data {
        var extensions = Data()

        // Basic Constraints (CA: false, pathLenConstraint: absent = can't issue certs)
        let bcOID = buildOID([2, 5, 29, 19])
        let bcCritical: [UInt8] = [0x01, 0x01, 0xFF] // BOOLEAN TRUE (critical)
        let bcValueSequence = buildSequence(Data()) // empty = CA:false
        let bcOctetString = buildOctetString(Data(bcValueSequence))
        var bcExtension = Data()
        bcExtension.append(contentsOf: bcOID)
        bcExtension.append(contentsOf: bcCritical)
        bcExtension.append(contentsOf: bcOctetString)
        extensions.append(contentsOf: buildSequence(bcExtension))

        // Key Usage (digitalSignature + keyEncipherment) — critical per RFC 5280
        let kuOID = buildOID([2, 5, 29, 15])
        let kuCritical: [UInt8] = [0x01, 0x01, 0xFF]
        let kuBits: [UInt8] = [0x05, 0xA0] // digitalSignature (bit 0) + keyEncipherment (bit 2)
        let kuBitString: [UInt8] = [0x03, 0x03, kuBits[0], kuBits[1], 0x00]
        let kuOctetString = buildOctetString(Data(kuBitString))
        var kuExtension = Data()
        kuExtension.append(contentsOf: kuOID)
        kuExtension.append(contentsOf: kuCritical)
        kuExtension.append(contentsOf: kuOctetString)
        extensions.append(contentsOf: buildSequence(kuExtension))

        // Extended Key Usage (serverAuth)
        let ekuOID = buildOID([2, 5, 29, 37])
        let serverAuthOID = buildOID([1, 3, 6, 1, 5, 5, 7, 3, 1])
        let ekuValueSequence = buildSequence(serverAuthOID)
        let ekuOctetString = buildOctetString(Data(ekuValueSequence))
        var ekuExtension = Data()
        ekuExtension.append(contentsOf: ekuOID)
        ekuExtension.append(contentsOf: ekuOctetString)
        extensions.append(contentsOf: buildSequence(ekuExtension))

        // Subject Alternative Name (DNS or IP)
        let sanOID = buildOID([2, 5, 29, 17])
        var sanValue = Data()
        if let ipBytes = parseIPAddress(hostname) {
            // IP address SAN: tag 7 (iPAddress)
            sanValue.append(contentsOf: buildImplicitTag(7, content: ipBytes))
        } else {
            // DNS name SAN: tag 2 (dNSName)
            sanValue.append(contentsOf: buildImplicitTag(2, content: [UInt8](hostname.utf8)))
        }
        let sanValueSequence = buildSequence(sanValue)
        let sanOctetString = buildOctetString(Data(sanValueSequence))
        var sanExtension = Data()
        sanExtension.append(contentsOf: sanOID)
        sanExtension.append(contentsOf: sanOctetString)
        extensions.append(contentsOf: buildSequence(sanExtension))

        return extensions
    }

    /// Parses an IP address string into bytes for SAN encoding.
    /// Returns 4 bytes for IPv4, 16 bytes for IPv6, nil if not an IP.
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

    func extractSubjectName(from certificate: SecCertificate) -> [UInt8]? {
        guard let certData = SecCertificateCopyData(certificate) as Data? else { return nil }
        let bytes = [UInt8](certData)
        guard bytes.count > 4, bytes[0] == 0x30 else { return nil }

        var offset = 1
        _ = parseLength(bytes, offset: &offset)
        guard offset < bytes.count, bytes[offset] == 0x30 else { return nil }
        offset += 1
        _ = parseLength(bytes, offset: &offset)

        guard offset < bytes.count else { return nil }
        if bytes[offset] == 0xA0 {
            offset += 1
            let vLen = parseLength(bytes, offset: &offset)
            guard offset + vLen <= bytes.count else { return nil }
            offset += vLen
        }

        guard offset < bytes.count, bytes[offset] == 0x02 else { return nil }
        offset += 1
        let serialLen = parseLength(bytes, offset: &offset)
        guard offset + serialLen <= bytes.count else { return nil }
        offset += serialLen

        guard offset < bytes.count, bytes[offset] == 0x30 else { return nil }
        offset += 1
        let sigAlgLen = parseLength(bytes, offset: &offset)
        guard offset + sigAlgLen <= bytes.count else { return nil }
        offset += sigAlgLen

        guard offset < bytes.count, bytes[offset] == 0x30 else { return nil }
        let issuerStart = offset
        offset += 1
        let issuerLen = parseLength(bytes, offset: &offset)
        let issuerTotalLen = 1 + lengthOfLength(issuerLen) + issuerLen
        guard issuerStart + issuerTotalLen <= bytes.count else { return nil }

        return Array(bytes[issuerStart..<(issuerStart + issuerTotalLen)])
    }

    func parseLength(_ bytes: [UInt8], offset: inout Int) -> Int {
        guard offset < bytes.count else { return 0 }
        let first = bytes[offset]
        offset += 1
        if first < 128 { return Int(first) }
        let numBytes = Int(first & 0x7F)
        var length = 0
        for _ in 0..<numBytes {
            guard offset < bytes.count else { return 0 }
            length = (length << 8) | Int(bytes[offset])
            offset += 1
        }
        return length
    }

    func lengthOfLength(_ length: Int) -> Int {
        if length < 128 { return 1 }
        var len = length
        var bytes = 0
        while len > 0 { bytes += 1; len >>= 8 }
        return bytes + 1
    }

    func signData(_ data: Data, with privateKey: SecKey) -> Data? {
        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else { return nil }
        var error: Unmanaged<CFError>?
        return SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data?
    }
}
