//
//  TLSInterceptor+ASN1.swift
//  IrisProxyExtension
//
//  Certificate building: serial numbers, DN, validity, SPKI, extensions.
//  DER primitives are in TLSInterceptor+DERPrimitives.swift.
//  DER parsing is in TLSInterceptor+DERParsing.swift.
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

        // Basic Constraints (CA: false)
        let bcOID = buildOID([2, 5, 29, 19])
        let bcCritical: [UInt8] = [0x01, 0x01, 0xFF]
        let bcValueSequence = buildSequence(Data())
        let bcOctetString = buildOctetString(Data(bcValueSequence))
        var bcExtension = Data()
        bcExtension.append(contentsOf: bcOID)
        bcExtension.append(contentsOf: bcCritical)
        bcExtension.append(contentsOf: bcOctetString)
        extensions.append(contentsOf: buildSequence(bcExtension))

        // Key Usage (digitalSignature + keyEncipherment)
        let kuOID = buildOID([2, 5, 29, 15])
        let kuCritical: [UInt8] = [0x01, 0x01, 0xFF]
        let kuBits: [UInt8] = [0x05, 0xA0]
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
            sanValue.append(contentsOf: buildImplicitTag(7, content: ipBytes))
        } else {
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
}
