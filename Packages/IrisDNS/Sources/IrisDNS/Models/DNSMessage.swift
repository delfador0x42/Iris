//
//  DNSMessage.swift
//  IrisDNS
//
//  DNS message models matching RFC 1035 wire format.
//

import Foundation

// MARK: - DNS Message

/// A complete DNS message (query or response).
public struct DNSMessage: Sendable, Codable, Equatable {
    /// Transaction ID
    public let id: UInt16
    /// Whether this is a response (true) or query (false)
    public let isResponse: Bool
    /// Operation code
    public let opcode: DNSOpcode
    /// Whether the responding server is authoritative
    public let isAuthoritative: Bool
    /// Whether the message was truncated
    public let isTruncated: Bool
    /// Whether recursion was desired (query) or available (response)
    public let recursionDesired: Bool
    public let recursionAvailable: Bool
    /// Response code
    public let responseCode: DNSResponseCode
    /// Questions
    public let questions: [DNSQuestion]
    /// Answer resource records
    public let answers: [DNSResourceRecord]
    /// Authority resource records
    public let authority: [DNSResourceRecord]
    /// Additional resource records
    public let additional: [DNSResourceRecord]

    /// The primary query name (first question's name).
    public var queryName: String? {
        questions.first?.name
    }

    /// The primary query type.
    public var queryType: DNSRecordType? {
        questions.first?.type
    }

    /// All answer values as a comma-separated string.
    public var answerSummary: String {
        answers.map { $0.displayValue }.joined(separator: ", ")
    }
}

// MARK: - DNS Question

/// A DNS question section entry.
public struct DNSQuestion: Sendable, Codable, Equatable {
    /// The domain name being queried
    public let name: String
    /// The query type (A, AAAA, CNAME, etc.)
    public let type: DNSRecordType
    /// Query class (usually 1 = IN)
    public let qclass: UInt16

    public init(name: String, type: DNSRecordType, qclass: UInt16 = 1) {
        self.name = name
        self.type = type
        self.qclass = qclass
    }
}

// MARK: - DNS Resource Record

/// A DNS resource record (answer, authority, or additional).
public struct DNSResourceRecord: Sendable, Codable, Equatable {
    /// The domain name this record is for
    public let name: String
    /// Record type
    public let type: DNSRecordType
    /// Record class (usually 1 = IN)
    public let rrclass: UInt16
    /// Time-to-live in seconds
    public let ttl: UInt32
    /// Raw record data
    public let rdata: Data
    /// Human-readable value (formatted from rdata)
    public let displayValue: String

    public init(name: String, type: DNSRecordType, rrclass: UInt16 = 1, ttl: UInt32, rdata: Data, displayValue: String) {
        self.name = name
        self.type = type
        self.rrclass = rrclass
        self.ttl = ttl
        self.rdata = rdata
        self.displayValue = displayValue
    }
}

// MARK: - DNS Record Type

/// DNS record types.
public enum DNSRecordType: Sendable, Codable, Equatable, Hashable {
    case a          // 1
    case ns         // 2
    case cname      // 5
    case soa        // 6
    case ptr        // 12
    case mx         // 15
    case txt        // 16
    case aaaa       // 28
    case srv        // 33
    case naptr      // 35
    case opt        // 41 (EDNS)
    case ds         // 43
    case rrsig      // 46
    case nsec       // 47
    case dnskey     // 48
    case https      // 65
    case svcb       // 64
    case any        // 255
    case unknown(Int)

    public var rawValue: Int {
        switch self {
        case .a: return 1
        case .ns: return 2
        case .cname: return 5
        case .soa: return 6
        case .ptr: return 12
        case .mx: return 15
        case .txt: return 16
        case .aaaa: return 28
        case .srv: return 33
        case .naptr: return 35
        case .opt: return 41
        case .ds: return 43
        case .rrsig: return 46
        case .nsec: return 47
        case .dnskey: return 48
        case .svcb: return 64
        case .https: return 65
        case .any: return 255
        case .unknown(let v): return v
        }
    }

    public var numericValue: Int { rawValue }

    public init?(rawValue: Int) {
        switch rawValue {
        case 1: self = .a
        case 2: self = .ns
        case 5: self = .cname
        case 6: self = .soa
        case 12: self = .ptr
        case 15: self = .mx
        case 16: self = .txt
        case 28: self = .aaaa
        case 33: self = .srv
        case 35: self = .naptr
        case 41: self = .opt
        case 43: self = .ds
        case 46: self = .rrsig
        case 47: self = .nsec
        case 48: self = .dnskey
        case 64: self = .svcb
        case 65: self = .https
        case 255: self = .any
        default: self = .unknown(rawValue)
        }
    }

    /// Short display name for the record type.
    public var displayName: String {
        switch self {
        case .a: return "A"
        case .ns: return "NS"
        case .cname: return "CNAME"
        case .soa: return "SOA"
        case .ptr: return "PTR"
        case .mx: return "MX"
        case .txt: return "TXT"
        case .aaaa: return "AAAA"
        case .srv: return "SRV"
        case .naptr: return "NAPTR"
        case .opt: return "OPT"
        case .ds: return "DS"
        case .rrsig: return "RRSIG"
        case .nsec: return "NSEC"
        case .dnskey: return "DNSKEY"
        case .svcb: return "SVCB"
        case .https: return "HTTPS"
        case .any: return "ANY"
        case .unknown(let v): return "TYPE\(v)"
        }
    }
}

// MARK: - DNS Opcode

/// DNS operation codes.
public enum DNSOpcode: Int, Sendable, Codable {
    case query = 0
    case inverseQuery = 1
    case status = 2
    case notify = 4
    case update = 5
}

// MARK: - DNS Response Code

/// DNS response codes (RCODE).
public enum DNSResponseCode: Int, Sendable, Codable {
    case noError = 0
    case formatError = 1
    case serverFailure = 2
    case nameError = 3      // NXDOMAIN
    case notImplemented = 4
    case refused = 5
    case yxDomain = 6
    case yxRRSet = 7
    case nxRRSet = 8
    case notAuth = 9
    case notZone = 10

    public var displayName: String {
        switch self {
        case .noError: return "NOERROR"
        case .formatError: return "FORMERR"
        case .serverFailure: return "SERVFAIL"
        case .nameError: return "NXDOMAIN"
        case .notImplemented: return "NOTIMP"
        case .refused: return "REFUSED"
        case .yxDomain: return "YXDOMAIN"
        case .yxRRSet: return "YXRRSET"
        case .nxRRSet: return "NXRRSET"
        case .notAuth: return "NOTAUTH"
        case .notZone: return "NOTZONE"
        }
    }

    public var isError: Bool {
        self != .noError
    }
}
