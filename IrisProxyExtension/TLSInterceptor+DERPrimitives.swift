import Foundation

/// Thin forwarding layer — all DER logic lives in Shared/DEREncoder.swift.
extension TLSInterceptor {
    func buildInteger(_ value: Int) -> [UInt8] { DEREncoder.buildInteger(value) }
    func buildInteger(_ data: Data) -> [UInt8] { DEREncoder.buildInteger(data) }
    func buildSequence(_ content: Data) -> [UInt8] { DEREncoder.buildSequence(content) }
    func buildSequence(_ content: [UInt8]) -> [UInt8] { DEREncoder.buildSequence(content) }
    func buildBitString(_ data: Data) -> [UInt8] { DEREncoder.buildBitString(data) }
    func buildOctetString(_ data: Data) -> [UInt8] { DEREncoder.buildOctetString(data) }
    func buildOID(_ oid: [UInt]) -> [UInt8] { DEREncoder.buildOID(oid) }
    func buildUTF8String(_ string: String) -> [UInt8] { DEREncoder.buildUTF8String(string) }
    func buildUTCTime(_ date: Date) -> [UInt8] { DEREncoder.buildUTCTime(date) }
    func buildExplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] { DEREncoder.buildExplicitTag(tag, content: content) }
    func buildImplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] { DEREncoder.buildImplicitTag(tag, content: content) }
    func buildSet(_ content: [UInt8]) -> [UInt8] { DEREncoder.buildSet(content) }
    func encodeLength(_ length: Int) -> [UInt8] { DEREncoder.encodeLength(length) }
}
