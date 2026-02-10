import Foundation
import Security

/// DER parsing and signature helpers for certificate building.
extension TLSInterceptor {

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
