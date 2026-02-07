import Foundation
import os.log

/// Service for querying GreyNoise threat intelligence
/// Community API (free, no key required)
/// Rate limit: ~100 requests/day
/// Identifies benign scanners (e.g., Shodan, Censys) vs malicious IPs
public actor GreyNoiseService {

    // MARK: - Singleton

    public static let shared = GreyNoiseService()

    // MARK: - Types

    public struct GreyNoiseResult: Sendable, Codable {
        public let ip: String
        public let noise: Bool           // true if seen scanning the internet
        public let riot: Bool            // true if benign service (CDN, cloud, etc)
        public let classification: String // "benign", "malicious", "unknown"
        public let name: String?         // Actor name (e.g., "Shodan.io")
        public let link: String?         // Link to GreyNoise visualizer
        public let lastSeen: String?     // Last time this IP was observed
        public let message: String?      // API message (for errors)

        enum CodingKeys: String, CodingKey {
            case ip
            case noise
            case riot
            case classification
            case name
            case link
            case lastSeen = "last_seen"
            case message
        }

        public init(
            ip: String,
            noise: Bool,
            riot: Bool,
            classification: String,
            name: String? = nil,
            link: String? = nil,
            lastSeen: String? = nil,
            message: String? = nil
        ) {
            self.ip = ip
            self.noise = noise
            self.riot = riot
            self.classification = classification
            self.name = name
            self.link = link
            self.lastSeen = lastSeen
            self.message = message
        }
    }

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "GreyNoiseService")
    private var cache = BoundedCache<GreyNoiseResult>(maxSize: 2000, ttl: 7200)
    private let endpoint = "https://api.greynoise.io/v3/community"

    /// Track daily request count to avoid hitting rate limit
    private var requestCount = 0
    private var requestCountResetDate = Date()
    private let dailyLimit = 100

    /// Whether to enable GreyNoise lookups (can be disabled by user)
    private var isEnabled = true

    // MARK: - Public Methods

    /// Enable or disable GreyNoise lookups
    public func setEnabled(_ enabled: Bool) {
        isEnabled = enabled
        logger.info("GreyNoise service \(enabled ? "enabled" : "disabled")")
    }

    /// Check if GreyNoise lookups are enabled and under rate limit
    public func isAvailable() -> Bool {
        guard isEnabled else { return false }
        resetDailyCountIfNeeded()
        return requestCount < dailyLimit
    }

    /// Look up threat intelligence for a single IP address
    /// - Parameter ip: The IP address to look up
    /// - Returns: GreyNoiseResult if successful, nil otherwise
    public func lookup(_ ip: String) async -> GreyNoiseResult? {
        // Check if service is available
        guard isAvailable() else {
            logger.debug("GreyNoise lookup skipped - rate limited or disabled")
            return nil
        }

        // Skip private IPs
        guard !isPrivateIP(ip) else { return nil }

        // Check cache
        if let cached = cache.get(ip) {
            return cached
        }

        // Fetch from API
        let result = await fetchSingle(ip)
        if let result = result {
            cache.set(ip, value: result)
        }
        return result
    }

    /// Batch lookup threat intelligence for multiple IP addresses
    /// Note: Due to rate limits, this should be used sparingly
    public func batchLookup(_ ips: [String]) async -> [String: GreyNoiseResult] {
        var results: [String: GreyNoiseResult] = [:]

        // GreyNoise has strict rate limits, so be conservative
        let publicIPs = ips.filter { !isPrivateIP($0) }
        var uncachedIPs: [String] = []

        // Start with cached results
        for ip in publicIPs {
            if let cached = cache.get(ip) {
                results[ip] = cached
            } else {
                uncachedIPs.append(ip)
            }
        }

        // Only fetch a limited number of new IPs
        let maxFetch = min(uncachedIPs.count, 10)  // Limit per batch
        for ip in uncachedIPs.prefix(maxFetch) {
            guard isAvailable() else { break }
            if let result = await lookup(ip) {
                results[ip] = result
            }
        }

        return results
    }

    /// Clear the cache
    public func clearCache() {
        cache.removeAll()
        logger.info("GreyNoise cache cleared")
    }

    // MARK: - Private Methods

    private func fetchSingle(_ ip: String) async -> GreyNoiseResult? {
        guard let url = URL(string: "\(endpoint)/\(ip)") else {
            return nil
        }

        // Increment request count
        requestCount += 1
        logger.debug("GreyNoise request #\(self.requestCount) for \(ip)")

        do {
            var request = URLRequest(url: url)
            request.setValue("application/json", forHTTPHeaderField: "Accept")

            let (data, response) = try await URLSession.shared.data(for: request)

            if let httpResponse = response as? HTTPURLResponse {
                // 404 means IP not in GreyNoise database - this is expected
                if httpResponse.statusCode == 404 {
                    return nil
                }
                // 429 means rate limited
                if httpResponse.statusCode == 429 {
                    logger.warning("GreyNoise rate limited")
                    return nil
                }
                if httpResponse.statusCode != 200 {
                    logger.warning("GreyNoise returned status \(httpResponse.statusCode) for \(ip)")
                    return nil
                }
            }

            let result = try JSONDecoder().decode(GreyNoiseResult.self, from: data)
            logger.debug("GreyNoise lookup success for \(ip): \(result.classification)")
            return result
        } catch {
            logger.error("GreyNoise lookup failed for \(ip): \(error.localizedDescription)")
            return nil
        }
    }

    /// Reset daily request count if we're in a new day
    private func resetDailyCountIfNeeded() {
        let calendar = Calendar.current
        if !calendar.isDateInToday(requestCountResetDate) {
            requestCount = 0
            requestCountResetDate = Date()
            logger.info("GreyNoise daily request count reset")
        }
    }

    /// Check if an IP address is private/local
    private func isPrivateIP(_ ip: String) -> Bool {
        if ip.hasPrefix("10.") ||
           ip.hasPrefix("192.168.") ||
           ip.hasPrefix("127.") ||
           ip.hasPrefix("0.") ||
           ip == "localhost" {
            return true
        }

        if ip.hasPrefix("172.") {
            let parts = ip.split(separator: ".")
            if parts.count >= 2, let second = Int(parts[1]) {
                if second >= 16 && second <= 31 {
                    return true
                }
            }
        }

        if ip == "::1" ||
           ip.lowercased().hasPrefix("fe80:") ||
           ip.lowercased().hasPrefix("fc") ||
           ip.lowercased().hasPrefix("fd") {
            return true
        }

        return false
    }
}
