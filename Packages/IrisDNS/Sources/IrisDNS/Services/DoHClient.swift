//
//  DoHClient.swift
//  IrisDNS
//
//  DNS-over-HTTPS client implementing RFC 8484.
//  Sends DNS wire format queries over HTTPS to configured DoH servers.
//

import Foundation
import os.log

/// DNS-over-HTTPS client (RFC 8484).
/// Sends standard DNS wire format messages over HTTPS POST requests.
public actor DoHClient {

    private let logger = Logger(subsystem: "com.wudan.iris", category: "DoHClient")

    /// The URL session for DoH requests.
    private let session: URLSession

    /// Active server configuration.
    private var serverConfig: DoHServerConfig

    /// Query statistics.
    private var totalQueries: Int = 0
    private var failedQueries: Int = 0
    private var totalLatencyMs: Double = 0

    // MARK: - Initialization

    public init(serverConfig: DoHServerConfig = .cloudflare) {
        self.serverConfig = serverConfig

        // Configure URL session for DoH
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 5
        config.timeoutIntervalForResource = 10
        config.httpMaximumConnectionsPerHost = 4

        // Use HTTP/2 for connection multiplexing
        config.httpAdditionalHeaders = [
            "Accept": "application/dns-message"
        ]

        self.session = URLSession(configuration: config)
    }

    // MARK: - Query

    /// Sends a DNS query via DoH and returns the response.
    /// - Parameter queryData: DNS wire format query message
    /// - Returns: DNS wire format response message
    public func query(_ queryData: Data) async throws -> Data {
        let startTime = CFAbsoluteTimeGetCurrent()
        totalQueries += 1

        guard let url = URL(string: serverConfig.url) else {
            failedQueries += 1
            throw DoHError.invalidServerURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.httpBody = queryData

        do {
            let (data, response) = try await session.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                failedQueries += 1
                throw DoHError.invalidResponse
            }

            guard httpResponse.statusCode == 200 else {
                failedQueries += 1
                logger.warning("DoH server returned status \(httpResponse.statusCode)")
                throw DoHError.httpError(httpResponse.statusCode)
            }

            guard !data.isEmpty else {
                failedQueries += 1
                throw DoHError.emptyResponse
            }

            let elapsed = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
            totalLatencyMs += elapsed

            logger.debug("DoH query completed in \(String(format: "%.1f", elapsed))ms (\(data.count) bytes)")

            return data
        } catch let error as DoHError {
            throw error
        } catch {
            failedQueries += 1
            logger.error("DoH query failed: \(error.localizedDescription)")
            throw DoHError.networkError(error)
        }
    }

    /// Sends a parsed DNS query and returns a parsed response.
    /// This is a convenience method that handles serialization.
    public func query(message: DNSMessage) async throws -> DNSMessage {
        let queryData = RustDNSParser.serialize(message)
        let responseData = try await query(queryData)

        guard let response = RustDNSParser.parse(responseData) else {
            throw DoHError.parseError
        }

        return response
    }

    /// Creates a DNS query message for a domain and record type.
    public func createQuery(domain: String, type: DNSRecordType = .a) -> DNSMessage {
        let id = UInt16.random(in: 0...UInt16.max)
        return DNSMessage(
            id: id,
            isResponse: false,
            opcode: .query,
            isAuthoritative: false,
            isTruncated: false,
            recursionDesired: true,
            recursionAvailable: false,
            responseCode: .noError,
            questions: [DNSQuestion(name: domain, type: type)],
            answers: [],
            authority: [],
            additional: []
        )
    }

    // MARK: - Configuration

    /// Updates the active DoH server.
    public func setServer(_ config: DoHServerConfig) {
        self.serverConfig = config
        logger.info("Switched DoH server to \(config.name) (\(config.url))")
    }

    /// Gets current statistics.
    public func getStatistics() -> DoHStatistics {
        DoHStatistics(
            totalQueries: totalQueries,
            failedQueries: failedQueries,
            averageLatencyMs: totalQueries > 0 ? totalLatencyMs / Double(totalQueries) : 0,
            serverName: serverConfig.name,
            serverURL: serverConfig.url
        )
    }

    /// Resets statistics.
    public func resetStatistics() {
        totalQueries = 0
        failedQueries = 0
        totalLatencyMs = 0
    }
}

// MARK: - DoH Errors

/// Errors from DoH operations.
public enum DoHError: Error, LocalizedError {
    case invalidServerURL
    case invalidResponse
    case httpError(Int)
    case emptyResponse
    case parseError
    case networkError(Error)

    public var errorDescription: String? {
        switch self {
        case .invalidServerURL: return "Invalid DoH server URL"
        case .invalidResponse: return "Invalid response from DoH server"
        case .httpError(let code): return "DoH server returned HTTP \(code)"
        case .emptyResponse: return "Empty response from DoH server"
        case .parseError: return "Failed to parse DNS response"
        case .networkError(let error): return "Network error: \(error.localizedDescription)"
        }
    }
}

// MARK: - Statistics

/// Statistics about DoH operations.
public struct DoHStatistics: Sendable {
    public let totalQueries: Int
    public let failedQueries: Int
    public let averageLatencyMs: Double
    public let serverName: String
    public let serverURL: String

    public var successRate: Double {
        guard totalQueries > 0 else { return 0 }
        return Double(totalQueries - failedQueries) / Double(totalQueries)
    }
}
