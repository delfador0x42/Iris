import Foundation

/// ASN.1 DER encoding primitives shared across certificate generation targets.
enum DEREncoder {

    static func buildInteger(_ value: Int) -> [UInt8] {
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

    static func buildInteger(_ data: Data) -> [UInt8] {
        var result: [UInt8] = [0x02]
        var bytes = [UInt8](data)
        if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
        result.append(contentsOf: encodeLength(bytes.count))
        result.append(contentsOf: bytes)
        return result
    }

    static func buildSequence(_ content: Data) -> [UInt8] {
        var result: [UInt8] = [0x30]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    static func buildSequence(_ content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [0x30]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    static func buildBitString(_ data: Data) -> [UInt8] {
        var result: [UInt8] = [0x03]
        result.append(contentsOf: encodeLength(data.count + 1))
        result.append(0)
        result.append(contentsOf: data)
        return result
    }

    static func buildOctetString(_ data: Data) -> [UInt8] {
        var result: [UInt8] = [0x04]
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    static func buildOID(_ oid: [UInt]) -> [UInt8] {
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

    static func encodeOIDComponent(_ value: UInt) -> [UInt8] {
        if value < 128 { return [UInt8(value)] }
        var bytes: [UInt8] = []
        var v = value
        while v > 0 {
            bytes.insert(UInt8(v & 0x7F) | (bytes.isEmpty ? 0 : 0x80), at: 0)
            v >>= 7
        }
        return bytes
    }

    static func buildUTF8String(_ string: String) -> [UInt8] {
        let data = Data(string.utf8)
        var result: [UInt8] = [0x0C]
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    static func buildUTCTime(_ date: Date) -> [UInt8] {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        formatter.timeZone = TimeZone(identifier: "UTC")
        let data = Data(formatter.string(from: date).utf8)
        var result: [UInt8] = [0x17]
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    static func buildExplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [UInt8(0xA0 + tag)]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    static func buildImplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [UInt8(0x80 + tag)]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    static func buildSet(_ content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [0x31]
        result.append(contentsOf: encodeLength(content.count))
        result.append(contentsOf: content)
        return result
    }

    static func buildBoolean(_ value: Bool) -> [UInt8] {
        [0x01, 0x01, value ? 0xFF : 0x00]
    }

    static func buildPrintableString(_ string: String) -> [UInt8] {
        let data = Data(string.utf8)
        var result: [UInt8] = [0x13]
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    static func buildGeneralizedTime(_ date: Date) -> [UInt8] {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        formatter.timeZone = TimeZone(identifier: "UTC")
        let data = Data(formatter.string(from: date).utf8)
        var result: [UInt8] = [0x18]
        result.append(contentsOf: encodeLength(data.count))
        result.append(contentsOf: data)
        return result
    }

    static func encodeLength(_ length: Int) -> [UInt8] {
        if length < 128 { return [UInt8(length)] }
        var bytes: [UInt8] = []
        var len = length
        while len > 0 { bytes.insert(UInt8(len & 0xFF), at: 0); len >>= 8 }
        return [UInt8(0x80 + bytes.count)] + bytes
    }
}
