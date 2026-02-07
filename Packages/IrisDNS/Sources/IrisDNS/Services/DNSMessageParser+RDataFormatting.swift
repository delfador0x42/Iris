import Foundation

// MARK: - RDATA Formatting

extension DNSMessageParser {

    /// Formats RDATA for display based on record type.
    static func formatRData(type: DNSRecordType, rdata: Data, bytes: [UInt8], rdataStart: Int) -> String {
        let rdataBytes = [UInt8](rdata)
        switch type {
        case .a:
            guard rdataBytes.count == 4 else { return rdata.hexString }
            return "\(rdataBytes[0]).\(rdataBytes[1]).\(rdataBytes[2]).\(rdataBytes[3])"

        case .aaaa:
            guard rdataBytes.count == 16 else { return rdata.hexString }
            var parts: [String] = []
            for i in stride(from: 0, to: 16, by: 2) {
                let value = UInt16(rdataBytes[i]) << 8 | UInt16(rdataBytes[i + 1])
                parts.append(String(format: "%x", value))
            }
            return parts.joined(separator: ":")

        case .cname, .ns, .ptr:
            if let (name, _) = parseName(bytes, offset: rdataStart) {
                return name
            }
            return rdata.hexString

        case .mx:
            guard rdataBytes.count >= 3 else { return rdata.hexString }
            let priority = UInt16(rdataBytes[0]) << 8 | UInt16(rdataBytes[1])
            if let (name, _) = parseName(bytes, offset: rdataStart + 2) {
                return "\(priority) \(name)"
            }
            return "\(priority) <unknown>"

        case .txt:
            // TXT records contain one or more character-strings
            var result: [String] = []
            var offset = 0
            while offset < rdataBytes.count {
                let len = Int(rdataBytes[offset])
                offset += 1
                guard offset + len <= rdataBytes.count else { break }
                if let text = String(bytes: rdataBytes[offset..<offset + len], encoding: .utf8) {
                    result.append(text)
                }
                offset += len
            }
            return result.joined(separator: " ")

        case .soa:
            if let (mname, offset1) = parseName(bytes, offset: rdataStart),
               let (rname, _) = parseName(bytes, offset: offset1) {
                return "\(mname) \(rname)"
            }
            return rdata.hexString

        case .srv:
            guard rdataBytes.count >= 7 else { return rdata.hexString }
            let priority = UInt16(rdataBytes[0]) << 8 | UInt16(rdataBytes[1])
            let weight = UInt16(rdataBytes[2]) << 8 | UInt16(rdataBytes[3])
            let port = UInt16(rdataBytes[4]) << 8 | UInt16(rdataBytes[5])
            if let (target, _) = parseName(bytes, offset: rdataStart + 6) {
                return "\(priority) \(weight) \(port) \(target)"
            }
            return "\(priority) \(weight) \(port)"

        case .https, .svcb:
            guard rdataBytes.count >= 3 else { return rdata.hexString }
            let priority = UInt16(rdataBytes[0]) << 8 | UInt16(rdataBytes[1])
            if let (target, _) = parseName(bytes, offset: rdataStart + 2) {
                return priority == 0 ? "AliasMode \(target)" : "\(priority) \(target)"
            }
            return rdata.hexString

        default:
            return rdata.hexString
        }
    }
}
