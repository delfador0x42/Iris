import Foundation

// MARK: - Name Parsing

extension DNSMessageParser {

    /// Parses a DNS name from wire format, handling compression pointers.
    static func parseName(_ bytes: [UInt8], offset: Int) -> (String, Int)? {
        var labels: [String] = []
        var currentOffset = offset
        var finalOffset: Int? = nil
        var totalLength = 0
        var jumps = 0

        while currentOffset < bytes.count {
            let length = Int(bytes[currentOffset])

            if length == 0 {
                // End of name
                if finalOffset == nil {
                    finalOffset = currentOffset + 1
                }
                break
            }

            if bytes[currentOffset] & compressionMask == compressionMask {
                // Compression pointer
                guard currentOffset + 1 < bytes.count else { return nil }
                let pointer = Int(UInt16(bytes[currentOffset] & ~compressionMask) << 8 | UInt16(bytes[currentOffset + 1]))
                if finalOffset == nil {
                    finalOffset = currentOffset + 2
                }
                currentOffset = pointer
                jumps += 1
                if jumps > 10 { return nil } // Prevent infinite loops
                continue
            }

            guard length <= maxLabelLength else { return nil }
            currentOffset += 1
            guard currentOffset + length <= bytes.count else { return nil }

            let label = String(bytes: bytes[currentOffset..<currentOffset + length], encoding: .utf8) ?? ""
            labels.append(label)
            totalLength += length + 1
            currentOffset += length

            guard totalLength <= maxNameLength else { return nil }
        }

        let name = labels.joined(separator: ".")
        return (name, finalOffset ?? currentOffset + 1)
    }

    /// Serializes a DNS name to wire format (without compression).
    static func serializeName(_ name: String) -> Data {
        var data = Data()
        let labels = name.split(separator: ".")
        for label in labels {
            let bytes = [UInt8](label.utf8)
            data.append(UInt8(bytes.count))
            data.append(contentsOf: bytes)
        }
        data.append(0) // Root label
        return data
    }

    // MARK: - Question Parsing

    static func parseQuestion(_ bytes: [UInt8], offset: Int) -> (DNSQuestion, Int)? {
        guard let (name, nameEnd) = parseName(bytes, offset: offset) else { return nil }
        guard nameEnd + 4 <= bytes.count else { return nil }

        let typeValue = UInt16(bytes[nameEnd]) << 8 | UInt16(bytes[nameEnd + 1])
        let qclass = UInt16(bytes[nameEnd + 2]) << 8 | UInt16(bytes[nameEnd + 3])
        let type = DNSRecordType(rawValue: Int(typeValue)) ?? .unknown(Int(typeValue))

        return (DNSQuestion(name: name, type: type, qclass: qclass), nameEnd + 4)
    }

    // MARK: - Resource Record Parsing

    static func parseResourceRecord(_ bytes: [UInt8], offset: Int) -> (DNSResourceRecord, Int)? {
        guard let (name, nameEnd) = parseName(bytes, offset: offset) else { return nil }
        guard nameEnd + 10 <= bytes.count else { return nil }

        let typeValue = UInt16(bytes[nameEnd]) << 8 | UInt16(bytes[nameEnd + 1])
        let rrclass = UInt16(bytes[nameEnd + 2]) << 8 | UInt16(bytes[nameEnd + 3])
        let ttl = UInt32(bytes[nameEnd + 4]) << 24 | UInt32(bytes[nameEnd + 5]) << 16 |
                  UInt32(bytes[nameEnd + 6]) << 8 | UInt32(bytes[nameEnd + 7])
        let rdLength = Int(UInt16(bytes[nameEnd + 8]) << 8 | UInt16(bytes[nameEnd + 9]))

        let rdataStart = nameEnd + 10
        guard rdataStart + rdLength <= bytes.count else { return nil }

        let type = DNSRecordType(rawValue: Int(typeValue)) ?? .unknown(Int(typeValue))
        let rdata = Data(bytes[rdataStart..<rdataStart + rdLength])
        let displayValue = formatRData(type: type, rdata: rdata, bytes: bytes, rdataStart: rdataStart)

        let record = DNSResourceRecord(
            name: name,
            type: type,
            rrclass: rrclass,
            ttl: ttl,
            rdata: rdata,
            displayValue: displayValue
        )

        return (record, rdataStart + rdLength)
    }

    static func serializeResourceRecord(_ record: DNSResourceRecord) -> Data {
        var data = Data()
        data.append(serializeName(record.name))
        let typeValue = UInt16(record.type.numericValue)
        data.append(UInt8(typeValue >> 8)); data.append(UInt8(typeValue & 0xFF))
        data.append(UInt8(record.rrclass >> 8)); data.append(UInt8(record.rrclass & 0xFF))
        data.append(UInt8(record.ttl >> 24)); data.append(UInt8((record.ttl >> 16) & 0xFF))
        data.append(UInt8((record.ttl >> 8) & 0xFF)); data.append(UInt8(record.ttl & 0xFF))
        let rdLength = UInt16(record.rdata.count)
        data.append(UInt8(rdLength >> 8)); data.append(UInt8(rdLength & 0xFF))
        data.append(record.rdata)
        return data
    }
}
