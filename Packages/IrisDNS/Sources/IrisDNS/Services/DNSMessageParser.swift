//
//  DNSMessageParser.swift
//  IrisDNS
//
//  Parses and serializes DNS wire format messages (RFC 1035).
//  Used by the DNS proxy to inspect queries and responses.
//

import Foundation
import os.log

/// Parser for DNS wire format messages (RFC 1035).
public final class DNSMessageParser: Sendable {

    static let logger = Logger(subsystem: "com.wudan.iris", category: "DNSMessageParser")

    // MARK: - Constants

    /// DNS header size is always 12 bytes
    static let headerSize = 12

    /// Maximum label length in a DNS name
    static let maxLabelLength = 63

    /// Maximum total name length
    static let maxNameLength = 253

    /// Compression pointer mask (top 2 bits set)
    static let compressionMask: UInt8 = 0xC0

    // MARK: - Parse

    /// Parses a DNS message from wire format data.
    public static func parse(_ data: Data) -> DNSMessage? {
        let bytes = [UInt8](data)
        guard bytes.count >= headerSize else {
            logger.warning("DNS message too short: \(bytes.count) bytes")
            return nil
        }

        // Parse header
        let id = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
        let flags = UInt16(bytes[2]) << 8 | UInt16(bytes[3])
        let qdCount = Int(UInt16(bytes[4]) << 8 | UInt16(bytes[5]))
        let anCount = Int(UInt16(bytes[6]) << 8 | UInt16(bytes[7]))
        let nsCount = Int(UInt16(bytes[8]) << 8 | UInt16(bytes[9]))
        let arCount = Int(UInt16(bytes[10]) << 8 | UInt16(bytes[11]))

        let isResponse = (flags & 0x8000) != 0
        let opcode = DNSOpcode(rawValue: Int((flags >> 11) & 0xF)) ?? .query
        let isAuthoritative = (flags & 0x0400) != 0
        let isTruncated = (flags & 0x0200) != 0
        let recursionDesired = (flags & 0x0100) != 0
        let recursionAvailable = (flags & 0x0080) != 0
        let responseCode = DNSResponseCode(rawValue: Int(flags & 0xF)) ?? .noError

        var offset = headerSize

        // Parse questions
        var questions: [DNSQuestion] = []
        for _ in 0..<qdCount {
            guard let (question, newOffset) = parseQuestion(bytes, offset: offset) else {
                logger.warning("Failed to parse DNS question at offset \(offset)")
                return nil
            }
            questions.append(question)
            offset = newOffset
        }

        // Parse answers
        var answers: [DNSResourceRecord] = []
        for _ in 0..<anCount {
            guard let (record, newOffset) = parseResourceRecord(bytes, offset: offset) else {
                break // Partial parsing OK for answers
            }
            answers.append(record)
            offset = newOffset
        }

        // Parse authority records
        var authority: [DNSResourceRecord] = []
        for _ in 0..<nsCount {
            guard let (record, newOffset) = parseResourceRecord(bytes, offset: offset) else {
                break
            }
            authority.append(record)
            offset = newOffset
        }

        // Parse additional records
        var additional: [DNSResourceRecord] = []
        for _ in 0..<arCount {
            guard let (record, newOffset) = parseResourceRecord(bytes, offset: offset) else {
                break
            }
            additional.append(record)
            offset = newOffset
        }

        return DNSMessage(
            id: id,
            isResponse: isResponse,
            opcode: opcode,
            isAuthoritative: isAuthoritative,
            isTruncated: isTruncated,
            recursionDesired: recursionDesired,
            recursionAvailable: recursionAvailable,
            responseCode: responseCode,
            questions: questions,
            answers: answers,
            authority: authority,
            additional: additional
        )
    }

    // MARK: - Serialize

    /// Serializes a DNS message to wire format.
    public static func serialize(_ message: DNSMessage) -> Data {
        var data = Data()

        // Header
        data.append(UInt8(message.id >> 8))
        data.append(UInt8(message.id & 0xFF))

        var flags: UInt16 = 0
        if message.isResponse { flags |= 0x8000 }
        flags |= UInt16(message.opcode.rawValue & 0xF) << 11
        if message.isAuthoritative { flags |= 0x0400 }
        if message.isTruncated { flags |= 0x0200 }
        if message.recursionDesired { flags |= 0x0100 }
        if message.recursionAvailable { flags |= 0x0080 }
        flags |= UInt16(message.responseCode.rawValue & 0xF)

        data.append(UInt8(flags >> 8))
        data.append(UInt8(flags & 0xFF))

        let qdCount = UInt16(message.questions.count)
        let anCount = UInt16(message.answers.count)
        let nsCount = UInt16(message.authority.count)
        let arCount = UInt16(message.additional.count)

        data.append(UInt8(qdCount >> 8)); data.append(UInt8(qdCount & 0xFF))
        data.append(UInt8(anCount >> 8)); data.append(UInt8(anCount & 0xFF))
        data.append(UInt8(nsCount >> 8)); data.append(UInt8(nsCount & 0xFF))
        data.append(UInt8(arCount >> 8)); data.append(UInt8(arCount & 0xFF))

        // Questions
        for question in message.questions {
            data.append(serializeName(question.name))
            data.append(UInt8(question.type.rawValue >> 8))
            data.append(UInt8(question.type.rawValue & 0xFF))
            data.append(UInt8(question.qclass >> 8))
            data.append(UInt8(question.qclass & 0xFF))
        }

        // Resource records
        for record in message.answers + message.authority + message.additional {
            data.append(serializeResourceRecord(record))
        }

        return data
    }
}

// MARK: - Data Extension

extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined(separator: " ")
    }
}
