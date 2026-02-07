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
        guard !isPrivateIP(ip) else { return nil }

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
    /// Returns dictionary mapping IP -> InternetDBResult
    public func batchLookup(_ ipAddresses: [String]) async -> [String: InternetDBResult] {
        // Filter out private IPs
        let publicIPs = ipAddresses.filter { !isPrivateIP($0) }

        guard !publicIPs.isEmpty else { return [:] }

        // Start with cached results
        var results: [String: InternetDBResult] = [:]
        var uncachedIPs: [String] = []

        for ip in publicIPs {
            if let cached = cache.get(ip) {
                results[ip] = cached
            } else {
                uncachedIPs.append(ip)
            }
        }

        // Nothing new to fetch
        guard !uncachedIPs.isEmpty else { return results }

        // InternetDB doesn't support batch API, so fetch concurrently
        // Limit concurrent requests to avoid overwhelming the API
        let maxConcurrent = 20

        await withTaskGroup(of: (String, InternetDBResult?).self) { group in
            for ip in uncachedIPs.prefix(maxConcurrent) {
                group.addTask {
                    let result = await self.lookup(ip)
                    return (ip, result)
                }
            }

            for await (ip, result) in group {
                if let result = result {
                    results[ip] = result
                }
            }
        }

        let successCount = results.count - (publicIPs.count - uncachedIPs.count)
        logger.info("InternetDB batch lookup: \(successCount)/\(uncachedIPs.count) IPs resolved")

        return results
    }

    /// Clear the cache
    public func clearCache() {
        cache.removeAll()
        logger.info("InternetDB cache cleared")
    }

    // MARK: - Private Methods

    /// Check if an IP address is private/local (not routable on the internet)
    private func isPrivateIP(_ ip: String) -> Bool {
        // IPv4 private ranges
        if ip.hasPrefix("10.") ||
           ip.hasPrefix("192.168.") ||
           ip.hasPrefix("127.") ||
           ip.hasPrefix("0.") ||
           ip == "localhost" {
            return true
        }

        // 172.16.0.0 - 172.31.255.255
        if ip.hasPrefix("172.") {
            let parts = ip.split(separator: ".")
            if parts.count >= 2, let second = Int(parts[1]) {
                if second >= 16 && second <= 31 {
                    return true
                }
            }
        }

        // IPv6 private/local
        if ip == "::1" ||
           ip.lowercased().hasPrefix("fe80:") ||
           ip.lowercased().hasPrefix("fc") ||
           ip.lowercased().hasPrefix("fd") {
            return true
        }

        return false
    }
}
