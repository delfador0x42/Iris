//
//  DNSQuery.swift
//  IrisDNS
//
//  Model for a captured DNS query, used in the DNS monitor UI.
//

import Foundation

/// A captured DNS query with its response.
public struct DNSQuery: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    /// When the query was made
    public let timestamp: Date
    /// Domain name queried
    public let domain: String
    /// Record type (A, AAAA, CNAME, etc.)
    public let recordType: DNSRecordType
    /// Process that made the query (if available)
    public let processName: String?
    /// Response code
    public var responseCode: DNSResponseCode?
    /// Resolved addresses/values
    public var answers: [String]
    /// TTL of the first answer
    public var ttl: UInt32?
    /// Query latency in milliseconds
    public var latencyMs: Double?
    /// Whether this was blocked by a filter
    public var isBlocked: Bool
    /// Whether this went through DoH (encrypted)
    public var isEncrypted: Bool

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        domain: String,
        recordType: DNSRecordType,
        processName: String? = nil,
        responseCode: DNSResponseCode? = nil,
        answers: [String] = [],
        ttl: UInt32? = nil,
        latencyMs: Double? = nil,
        isBlocked: Bool = false,
        isEncrypted: Bool = true
    ) {
        self.id = id
        self.timestamp = timestamp
        self.domain = domain
        self.recordType = recordType
        self.processName = processName
        self.responseCode = responseCode
        self.answers = answers
        self.ttl = ttl
        self.latencyMs = latencyMs
        self.isBlocked = isBlocked
        self.isEncrypted = isEncrypted
    }

    /// Whether the query was successful.
    public var isSuccess: Bool {
        responseCode == .noError && !answers.isEmpty
    }

    /// Whether this was an NXDOMAIN response.
    public var isNXDomain: Bool {
        responseCode == .nameError
    }

    /// The primary answer (first resolved address).
    public var primaryAnswer: String? {
        answers.first
    }

    /// Domain with TLD extracted (e.g., "apple.com" from "api.apple.com").
    public var rootDomain: String {
        let parts = domain.split(separator: ".")
        if parts.count >= 2 {
            return parts.suffix(2).joined(separator: ".")
        }
        return domain
    }
}

// MARK: - DNS Configuration

/// Configuration for DNS-over-HTTPS servers.
public struct DoHServerConfig: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    /// Display name
    public let name: String
    /// DoH endpoint URL
    public let url: String
    /// Server IPs for bootstrap (avoids chicken-and-egg DNS resolution)
    public let bootstrapIPs: [String]
    /// Whether this server is currently active
    public var isActive: Bool

    public init(
        id: UUID = UUID(),
        name: String,
        url: String,
        bootstrapIPs: [String],
        isActive: Bool = false
    ) {
        self.id = id
        self.name = name
        self.url = url
        self.bootstrapIPs = bootstrapIPs
        self.isActive = isActive
    }

    /// Cloudflare 1.1.1.1
    public static let cloudflare = DoHServerConfig(
        name: "Cloudflare",
        url: "https://cloudflare-dns.com/dns-query",
        bootstrapIPs: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
        isActive: true
    )

    /// Cloudflare security (malware blocking)
    public static let cloudflareFamily = DoHServerConfig(
        name: "Cloudflare Family",
        url: "https://family.cloudflare-dns.com/dns-query",
        bootstrapIPs: ["1.1.1.3", "1.0.0.3"],
        isActive: false
    )

    /// Google DNS
    public static let google = DoHServerConfig(
        name: "Google",
        url: "https://dns.google/dns-query",
        bootstrapIPs: ["8.8.8.8", "8.8.4.4"],
        isActive: false
    )

    /// Quad9
    public static let quad9 = DoHServerConfig(
        name: "Quad9",
        url: "https://dns.quad9.net/dns-query",
        bootstrapIPs: ["9.9.9.9", "149.112.112.112"],
        isActive: false
    )

    /// All available servers.
    public static let allServers: [DoHServerConfig] = [
        .cloudflare, .cloudflareFamily, .google, .quad9
    ]
}
