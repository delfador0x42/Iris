import Foundation

/// Rust-backed DNS wire format parser. Drop-in replacement for DNSMessageParser.
enum RustDNSParser {

    static func parse(_ data: Data) -> DNSMessage? {
        var msg = IrisDnsMessage()
        let rc = data.withUnsafeBytes { buf in
            iris_dns_parse(
                buf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                buf.count, &msg
            )
        }
        guard rc == 0 else { return nil }
        defer { iris_dns_free_message(&msg) }

        let questions = (0..<msg.questions_count).map { i -> DNSQuestion in
            let q = msg.questions.advanced(by: i).pointee
            let name = q.name.map { String(cString: $0) } ?? ""
            return DNSQuestion(
                name: name,
                type: DNSRecordType(rawValue: Int(q.record_type)) ?? .unknown(Int(q.record_type)),
                qclass: q.qclass
            )
        }

        let answers = records(msg.answers, count: msg.answers_count)
        let authority = records(msg.authority, count: msg.authority_count)
        let additional = records(msg.additional, count: msg.additional_count)

        return DNSMessage(
            id: msg.id,
            isResponse: msg.is_response,
            opcode: DNSOpcode(rawValue: Int(msg.opcode)) ?? .query,
            isAuthoritative: msg.is_authoritative,
            isTruncated: msg.is_truncated,
            recursionDesired: msg.recursion_desired,
            recursionAvailable: msg.recursion_available,
            responseCode: DNSResponseCode(rawValue: Int(msg.response_code)) ?? .noError,
            questions: questions,
            answers: answers,
            authority: authority,
            additional: additional
        )
    }

    static func serialize(_ message: DNSMessage) -> Data {
        // For queries, use the optimized build_query path
        if !message.isResponse, let q = message.questions.first {
            var outData: UnsafeMutablePointer<UInt8>?
            var outLen: Int = 0
            let rc = q.name.withCString { domain in
                iris_dns_build_query(
                    domain, UInt16(q.type.numericValue), message.id,
                    message.recursionDesired, &outData, &outLen
                )
            }
            if rc == 0, let ptr = outData, outLen > 0 {
                defer { iris_free_bytes(ptr, outLen) }
                return Data(bytes: ptr, count: outLen)
            }
        }
        // Fallback to Swift serializer for complex messages
        return DNSMessageParser.serialize(message)
    }

    private static func records(_ ptr: UnsafeMutablePointer<IrisDnsRecord>?,
                                count: Int) -> [DNSResourceRecord] {
        guard count > 0, let ptr = ptr else { return [] }
        return (0..<count).map { i in
            let r = ptr.advanced(by: i).pointee
            let name = r.name.map { String(cString: $0) } ?? ""
            let display = r.display_value.map { String(cString: $0) } ?? ""
            let rdata: Data
            if r.rdata_len > 0, let rd = r.rdata {
                rdata = Data(bytes: rd, count: r.rdata_len)
            } else {
                rdata = Data()
            }
            return DNSResourceRecord(
                name: name,
                type: DNSRecordType(rawValue: Int(r.record_type)) ?? .unknown(Int(r.record_type)),
                rrclass: r.rrclass,
                ttl: r.ttl,
                rdata: rdata,
                displayValue: display
            )
        }
    }
}
