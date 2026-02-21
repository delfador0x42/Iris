//
//  DoHClient.swift
//  IrisProxyExtension
//
//  DNS-over-HTTPS client. Sends DNS wire format queries to configurable
//  DoH servers via HTTPS POST (RFC 8484). Uses bootstrap IPs to avoid
//  chicken-and-egg DNS resolution. Traffic from within the extension
//  automatically bypasses the proxy's own interception.
//

import Foundation
import Network
import os.log

/// DNS-over-HTTPS client for the proxy extension.
final class DoHClient: @unchecked Sendable {

    private let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "DoHClient")

    /// URL session configured for DoH
    private let session: URLSession

    /// Current server configuration (guarded by configLock)
    private var serverURL: URL
    private var fallbackURL: URL?
    private let configLock = NSLock()

    // MARK: - Server Configurations

    private struct ServerConfig {
        let name: String
        let primaryURL: String
        let fallbackURL: String?
    }

    private static let servers: [String: ServerConfig] = [
        "Cloudflare": ServerConfig(
            name: "Cloudflare",
            primaryURL: "https://1.1.1.1/dns-query",
            fallbackURL: "https://1.0.0.1/dns-query"
        ),
        "Cloudflare Family": ServerConfig(
            name: "Cloudflare Family",
            primaryURL: "https://1.1.1.3/dns-query",
            fallbackURL: "https://1.0.0.3/dns-query"
        ),
        "Google": ServerConfig(
            name: "Google",
            primaryURL: "https://8.8.8.8/dns-query",
            fallbackURL: "https://8.8.4.4/dns-query"
        ),
        "Quad9": ServerConfig(
            name: "Quad9",
            primaryURL: "https://9.9.9.9:5053/dns-query",
            fallbackURL: "https://149.112.112.112:5053/dns-query"
        )
    ]

    // MARK: - Initialization

    init() {
        self.serverURL = URL(string: "https://1.1.1.1/dns-query")!
        self.fallbackURL = URL(string: "https://1.0.0.1/dns-query")

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 5
        config.timeoutIntervalForResource = 10
        config.httpMaximumConnectionsPerHost = 4
        config.httpAdditionalHeaders = [
            "Accept": "application/dns-message"
        ]

        self.session = URLSession(configuration: config)
    }

    // MARK: - Query

    struct QueryResult {
        let data: Data
        let isEncrypted: Bool
    }

    /// Sends a DNS wire format query via DoH and returns the wire format response.
    /// Falls back to direct UDP DNS if all DoH servers are unreachable.
    func query(_ queryData: Data) async throws -> QueryResult {
        let (primary, fallback) = getServerURLs()

        var request = URLRequest(url: primary)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.httpBody = queryData

        do {
            let (data, response) = try await session.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw DoHError.invalidResponse
            }

            guard httpResponse.statusCode == 200 else {
                if let fallback = fallback {
                    return try await queryFallback(queryData, url: fallback)
                }
                throw DoHError.httpError(httpResponse.statusCode)
            }

            guard !data.isEmpty else {
                throw DoHError.emptyResponse
            }

            return QueryResult(data: data, isEncrypted: true)

        } catch is DoHError {
            let data = try await directDNSFallback(queryData)
            return QueryResult(data: data, isEncrypted: false)
        } catch {
            if let fallback = fallback {
                do {
                    return try await queryFallback(queryData, url: fallback)
                } catch {}
            }
            do {
                let data = try await directDNSFallback(queryData)
                return QueryResult(data: data, isEncrypted: false)
            } catch {}
            throw DoHError.networkError(error)
        }
    }

    private func queryFallback(_ queryData: Data, url: URL) async throws -> QueryResult {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.httpBody = queryData

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200,
              !data.isEmpty else {
            throw DoHError.fallbackFailed
        }

        return QueryResult(data: data, isEncrypted: true)
    }

    /// Last-resort: send raw DNS query via UDP to 8.8.8.8:53.
    private func directDNSFallback(_ queryData: Data) async throws -> Data {
        logger.warning("DoH unreachable, falling back to direct DNS")
        return try await withCheckedThrowingContinuation { continuation in
            let resumed = AtomicFlag()

            let connection = NWConnection(
                host: NWEndpoint.Host("8.8.8.8"),
                port: NWEndpoint.Port(rawValue: 53)!,
                using: .udp
            )

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    guard !resumed.isSet else { return }
                    connection.send(content: queryData, completion: .contentProcessed { error in
                        if let error = error {
                            guard resumed.trySet() else { return }
                            connection.cancel()
                            continuation.resume(throwing: error)
                            return
                        }
                        connection.receiveMessage { data, _, _, error in
                            guard resumed.trySet() else { return }
                            connection.cancel()
                            if let data = data, !data.isEmpty {
                                continuation.resume(returning: data)
                            } else {
                                continuation.resume(throwing: error ?? DoHError.emptyResponse)
                            }
                        }
                    })
                case .failed(let error):
                    guard resumed.trySet() else { return }
                    connection.cancel()
                    continuation.resume(throwing: error)
                case .cancelled:
                    guard resumed.trySet() else { return }
                    continuation.resume(throwing: DoHError.fallbackFailed)
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .userInitiated))

            DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
                guard resumed.trySet() else { return }
                connection.cancel()
                continuation.resume(throwing: DoHError.fallbackFailed)
            }
        }
    }

    // MARK: - Configuration

    func setServer(_ name: String) {
        guard let config = Self.servers[name] else {
            logger.warning("Unknown server name: \(name), keeping current")
            return
        }
        configLock.lock()
        defer { configLock.unlock() }
        serverURL = URL(string: config.primaryURL)!
        fallbackURL = config.fallbackURL.flatMap { URL(string: $0) }
        logger.info("DoH server switched to \(name) (\(config.primaryURL))")
    }

    private func getServerURLs() -> (primary: URL, fallback: URL?) {
        configLock.lock()
        defer { configLock.unlock() }
        return (serverURL, fallbackURL)
    }
}

// MARK: - Errors

enum DoHError: Error, LocalizedError {
    case invalidResponse
    case httpError(Int)
    case emptyResponse
    case networkError(Error)
    case fallbackFailed

    var errorDescription: String? {
        switch self {
        case .invalidResponse: return "Invalid response from DoH server"
        case .httpError(let code): return "DoH server returned HTTP \(code)"
        case .emptyResponse: return "Empty response from DoH server"
        case .networkError(let error): return "Network error: \(error.localizedDescription)"
        case .fallbackFailed: return "Both primary and fallback DoH servers failed"
        }
    }
}
