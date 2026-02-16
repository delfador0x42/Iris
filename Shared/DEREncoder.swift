import Foundation

/// ASN.1 DER encoding primitives shared across certificate generation targets.
/// Delegates to RustDEREncoder for all encoding operations.
enum DEREncoder {

    static func buildInteger(_ value: Int) -> [UInt8] { RustDEREncoder.buildInteger(value) }
    static func buildInteger(_ data: Data) -> [UInt8] { RustDEREncoder.buildInteger(data) }
    static func buildSequence(_ content: Data) -> [UInt8] { RustDEREncoder.buildSequence(content) }
    static func buildSequence(_ content: [UInt8]) -> [UInt8] { RustDEREncoder.buildSequence(content) }
    static func buildBitString(_ data: Data) -> [UInt8] { RustDEREncoder.buildBitString(data) }
    static func buildOctetString(_ data: Data) -> [UInt8] { RustDEREncoder.buildOctetString(data) }
    static func buildOID(_ oid: [UInt]) -> [UInt8] { RustDEREncoder.buildOID(oid) }
    static func buildUTF8String(_ string: String) -> [UInt8] { RustDEREncoder.buildUTF8String(string) }
    static func buildUTCTime(_ date: Date) -> [UInt8] { RustDEREncoder.buildUTCTime(date) }
    static func buildExplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] { RustDEREncoder.buildExplicitTag(tag, content: content) }
    static func buildImplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] { RustDEREncoder.buildImplicitTag(tag, content: content) }
    static func buildSet(_ content: [UInt8]) -> [UInt8] { RustDEREncoder.buildSet(content) }
    static func buildBoolean(_ value: Bool) -> [UInt8] { RustDEREncoder.buildBoolean(value) }
    static func buildPrintableString(_ string: String) -> [UInt8] { RustDEREncoder.buildPrintableString(string) }
    static func buildGeneralizedTime(_ date: Date) -> [UInt8] { RustDEREncoder.buildGeneralizedTime(date) }

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

    static func encodeLength(_ length: Int) -> [UInt8] {
        if length < 128 { return [UInt8(length)] }
        var bytes: [UInt8] = []
        var len = length
        while len > 0 { bytes.insert(UInt8(len & 0xFF), at: 0); len >>= 8 }
        return [UInt8(0x80 + bytes.count)] + bytes
    }
}
