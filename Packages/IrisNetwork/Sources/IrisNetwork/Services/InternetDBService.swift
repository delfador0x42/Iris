import Foundation
import os.log

/// Service for fetching open ports, hostnames, and vulnerabilities from Shodan's free InternetDB API
/// API docs: https://internetdb.shodan.io/
/// No API key required, returns data for IPs that Shodan has scanned
public actor InternetDBService {

    // MARK: - Singleton

    public static let shared = InternetDBService()

    // MARK: - Types

    public struct InternetDBResult: Sendable, Codable {
        public let ip: String
        public let ports: [Int]
        public let hostnames: [String]
        public let cpes: [String]       // Common Platform Enumeration (software/hardware IDs)
        public let tags: [String]       // Service tags: vpn, proxy, botnet, tor, etc.
        public let vulns: [String]      // CVE identifiers

        /// Convert ports to UInt16 array for storage
        public var portsAsUInt16: [UInt16] {
            ports.compactMap { UInt16(exactly: $0) }
        }
    }

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "InternetDBService")
    private var cache = BoundedCache<InternetDBResult>(maxSize: 5000, ttl: 3600)
    private let endpoint = "https://internetdb.shodan.io"

    // MARK: - Public Methods

    /// Look up security data for a single IP address
    public func lookup(_ ip: String) async -> InternetDBResult? {
        // Skip private IPs - InternetDB only has data for public IPs
        guard !EnrichmentHelpers.isPrivateIP(ip) else { return nil }

        // Check cache first
        if let cached = cache.get(ip) {
            return cached
        }

        guard let url = URL(string: "\(endpoint)/\(ip)") else {
            logger.error("Invalid URL for IP: \(ip)")
            return nil
        }

        do {
            let (data, response) = try await URLSession.shared.data(from: url)

            // 404 means IP not in database (not scanned by Shodan) - this is expected
            if let httpResponse = response as? HTTPURLResponse {
                if httpResponse.statusCode == 404 {
                    return nil
                }
                if httpResponse.statusCode != 200 {
                    logger.warning("InternetDB returned status \(httpResponse.statusCode) for \(ip)")
                    return nil
                }
            }

            let result = try JSONDecoder().decode(InternetDBResult.self, from: data)
            cache.set(ip, value: result)
            logger.debug("InternetDB lookup success for \(ip): \(result.ports.count) ports, \(result.vulns.count) vulns")
            return result
        } catch {
            logger.error("InternetDB lookup failed for \(ip): \(error.localizedDescription)")
            return nil
        }
    }

    /// Look up security data for multiple IP addresses concurrently
    public func batchLookup(_ ips: [String]) async -> [String: InternetDBResult] {
        await EnrichmentHelpers.batchLookup(ips, maxConcurrent: 20, lookup: lookup)
    }

    /// Clear the cache
    public func clearCache() { cache.removeAll() }

}
