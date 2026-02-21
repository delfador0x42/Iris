//
//  DNSParsing.swift
//  IrisProxyExtension
//
//  DNS wire format parsing helpers. Standalone functions (not extension methods)
//  for parsing DNS query/response packets and building SERVFAIL responses.
//

import Foundation

// MARK: - DNS Query/Response Info

struct DNSQueryInfo {
    let domain: String
    let type: String
}

struct DNSResponseInfo {
    let responseCode: String
    let answers: [String]
    let ttl: UInt32?
}

// MARK: - Parsing

func parseDNSQueryInfo(_ data: Data) -> DNSQueryInfo {
    guard data.count >= 12 else {
        return DNSQueryInfo(domain: "unknown", type: "UNKNOWN")
    }

    var offset = 12
    var labels: [String] = []
    while offset < data.count {
        let length = Int(data[offset])
        offset += 1
        if length == 0 { break }
        if offset + length > data.count { break }
        let label = String(data: data[offset..<offset+length], encoding: .utf8) ?? ""
        labels.append(label)
        offset += length
    }

    var type = "UNKNOWN"
    if offset + 2 <= data.count {
        let qtype = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        type = dnsTypeString(qtype)
    }
    return DNSQueryInfo(domain: labels.joined(separator: "."), type: type)
}

func parseDNSResponseInfo(_ data: Data) -> DNSResponseInfo {
    guard data.count >= 12 else {
        return DNSResponseInfo(responseCode: "UNKNOWN", answers: [], ttl: nil)
    }

    let rcode = data[3] & 0x0F
    let responseCode = dnsRcodeString(rcode)
    let ancount = UInt16(data[6]) << 8 | UInt16(data[7])
    guard ancount > 0 else {
        return DNSResponseInfo(responseCode: responseCode, answers: [], ttl: nil)
    }

    var offset = 12
    let qdcount = UInt16(data[4]) << 8 | UInt16(data[5])
    for _ in 0..<qdcount {
        offset = skipDNSName(data, offset: offset)
        offset += 4
    }

    var answers: [String] = []
    var firstTTL: UInt32?

    for _ in 0..<ancount {
        guard offset + 10 <= data.count else { break }
        offset = skipDNSName(data, offset: offset)
        guard offset + 10 <= data.count else { break }

        let atype = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        offset += 4

        let ttl = UInt32(data[offset]) << 24 | UInt32(data[offset+1]) << 16 |
                   UInt32(data[offset+2]) << 8 | UInt32(data[offset+3])
        offset += 4
        if firstTTL == nil { firstTTL = ttl }

        let rdlength = Int(UInt16(data[offset]) << 8 | UInt16(data[offset + 1]))
        offset += 2
        guard offset + rdlength <= data.count else { break }

        switch atype {
        case 1 where rdlength == 4:
            answers.append("\(data[offset]).\(data[offset+1]).\(data[offset+2]).\(data[offset+3])")
        case 28 where rdlength == 16:
            var parts: [String] = []
            for i in stride(from: 0, to: 16, by: 2) {
                let word = UInt16(data[offset + i]) << 8 | UInt16(data[offset + i + 1])
                parts.append(String(format: "%x", word))
            }
            answers.append(parts.joined(separator: ":"))
        case 5:
            answers.append(readDNSName(data, offset: offset))
        default:
            answers.append("[\(dnsTypeString(atype))]")
        }
        offset += rdlength
    }
    return DNSResponseInfo(responseCode: responseCode, answers: answers, ttl: firstTTL)
}

func buildServfailResponse(for query: Data) -> Data? {
    guard query.count >= 12 else { return nil }
    var response = Data(count: 12)
    response[0] = query[0]
    response[1] = query[1]
    response[2] = 0x80     // QR=1 (response)
    response[3] = 0x02     // RCODE=SERVFAIL
    return response
}

// MARK: - DNS Name Helpers

func skipDNSName(_ data: Data, offset: Int) -> Int {
    var pos = offset
    while pos < data.count {
        let b = data[pos]
        if b == 0 { return pos + 1 }
        if b & 0xC0 == 0xC0 {
            return min(pos + 2, data.count)
        }
        let next = pos + Int(b) + 1
        guard next <= data.count else { return data.count }
        pos = next
    }
    return pos
}

func readDNSName(_ data: Data, offset: Int) -> String {
    var labels: [String] = []
    var pos = offset
    var jumps = 0
    while pos < data.count && jumps < 10 {
        let b = data[pos]
        if b == 0 { break }
        if b & 0xC0 == 0xC0 {
            guard pos + 1 < data.count else { break }
            pos = Int(b & 0x3F) << 8 | Int(data[pos + 1])
            jumps += 1
            continue
        }
        let length = Int(b)
        pos += 1
        guard pos + length <= data.count else { break }
        if let label = String(data: data[pos..<pos+length], encoding: .utf8) { labels.append(label) }
        pos += length
    }
    return labels.joined(separator: ".")
}

func dnsTypeString(_ type: UInt16) -> String {
    switch type {
    case 1: return "A"; case 2: return "NS"; case 5: return "CNAME"
    case 6: return "SOA"; case 12: return "PTR"; case 15: return "MX"
    case 16: return "TXT"; case 28: return "AAAA"; case 33: return "SRV"
    case 65: return "HTTPS"; default: return "TYPE\(type)"
    }
}

func dnsRcodeString(_ rcode: UInt8) -> String {
    switch rcode {
    case 0: return "NOERROR"; case 1: return "FORMERR"; case 2: return "SERVFAIL"
    case 3: return "NXDOMAIN"; case 4: return "NOTIMP"; case 5: return "REFUSED"
    default: return "RCODE\(rcode)"
    }
}
