import Foundation
import os.log

/// Service for querying AbuseIPDB threat intelligence
/// Free tier: 1,000 requests/day (requires API key)
/// Provides abuse confidence scores and reports
public actor AbuseIPDBService {

    // MARK: - Singleton

    public static let shared = AbuseIPDBService()

    // MARK: - Types

    public struct AbuseResult: Sendable, Codable {
        public let ipAddress: String
        public let abuseConfidenceScore: Int  // 0-100
        public let countryCode: String?
        public let usageType: String?         // "Data Center/Web Hosting/Transit"
        public let isp: String?
        public let domain: String?
        public let isTor: Bool
        public let isWhitelisted: Bool?
        public let totalReports: Int
        public let numDistinctUsers: Int?
        public let lastReportedAt: String?

        public init(
            ipAddress: String,
            abuseConfidenceScore: Int,
            countryCode: String? = nil,
            usageType: String? = nil,
            isp: String? = nil,
            domain: String? = nil,
            isTor: Bool = false,
            isWhitelisted: Bool? = nil,
            totalReports: Int = 0,
            numDistinctUsers: Int? = nil,
            lastReportedAt: String? = nil
        ) {
            self.ipAddress = ipAddress
            self.abuseConfidenceScore = abuseConfidenceScore
            self.countryCode = countryCode
            self.usageType = usageType
            self.isp = isp
            self.domain = domain
            self.isTor = isTor
            self.isWhitelisted = isWhitelisted
            self.totalReports = totalReports
            self.numDistinctUsers = numDistinctUsers
            self.lastReportedAt = lastReportedAt
        }
    }

    /// API response wrapper
    private struct APIResponse: Codable {
        let data: AbuseData

        struct AbuseData: Codable {
            let ipAddress: String
            let abuseConfidenceScore: Int
            let countryCode: String?
            let usageType: String?
            let isp: String?
            let domain: String?
            let isTor: Bool
            let isWhitelisted: Bool?
            let totalReports: Int
            let numDistinctUsers: Int?
            let lastReportedAt: String?
        }
    }

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "AbuseIPDBService")
    private var cache = BoundedCache<AbuseResult>(maxSize: 2000, ttl: 7200)
    private let endpoint = "https://api.abuseipdb.com/api/v2/check"

    /// API key (required for AbuseIPDB)
    private var apiKey: String?

    /// Track daily request count
    private var requestCount = 0
    private var requestCountResetDate = Date()
    private let dailyLimit = 1000

    // MARK: - Public Methods

    /// Set the API key for AbuseIPDB
    /// Get a free key at https://www.abuseipdb.com/account/api
    public func setAPIKey(_ key: String?) {
        apiKey = key?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let key = apiKey, !key.isEmpty {
            logger.info("AbuseIPDB API key configured")
        } else {
            logger.info("AbuseIPDB API key cleared")
        }
    }

    /// Check if AbuseIPDB is configured and available
    public func isAvailable() -> Bool {
        guard let key = apiKey, !key.isEmpty else { return false }
        resetDailyCountIfNeeded()
        return requestCount < dailyLimit
    }

    /// Look up abuse score for a single IP address
    /// - Parameter ip: The IP address to look up
    /// - Returns: AbuseResult if successful, nil otherwise
    public func lookup(_ ip: String) async -> AbuseResult? {
        // Check if API key is configured
        guard isAvailable() else {
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

    /// Batch lookup abuse scores for multiple IP addresses
    public func batchLookup(_ ips: [String]) async -> [String: AbuseResult] {
        var results: [String: AbuseResult] = [:]

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

        // Fetch uncached IPs concurrently
        let maxFetch = min(uncachedIPs.count, 20)  // Limit per batch

        await withTaskGroup(of: (String, AbuseResult?).self) { group in
            for ip in uncachedIPs.prefix(maxFetch) {
                guard isAvailable() else { break }
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

        return results
    }

    /// Clear the cache
    public func clearCache() {
        cache.removeAll()
        logger.info("AbuseIPDB cache cleared")
    }

    // MARK: - Private Methods

    private func fetchSingle(_ ip: String) async -> AbuseResult? {
        guard let apiKey = apiKey, !apiKey.isEmpty else {
            return nil
        }

        guard var urlComponents = URLComponents(string: endpoint) else {
            return nil
        }
        urlComponents.queryItems = [
            URLQueryItem(name: "ipAddress", value: ip),
            URLQueryItem(name: "maxAgeInDays", value: "90"),  // Reports from last 90 days
            URLQueryItem(name: "verbose", value: "false")
        ]

        guard let url = urlComponents.url else {
            return nil
        }

        // Increment request count
        requestCount += 1
        logger.debug("AbuseIPDB request #\(self.requestCount) for \(ip)")

        do {
            var request = URLRequest(url: url)
            request.setValue(apiKey, forHTTPHeaderField: "Key")
            request.setValue("application/json", forHTTPHeaderField: "Accept")

            let (responseData, response) = try await URLSession.shared.data(for: request)

            if let httpResponse = response as? HTTPURLResponse {
                // 401 means invalid API key
                if httpResponse.statusCode == 401 {
                    logger.warning("AbuseIPDB API key invalid")
                    return nil
                }
                // 402 means over daily limit
                if httpResponse.statusCode == 402 {
                    logger.warning("AbuseIPDB daily limit exceeded")
                    return nil
                }
                // 429 means rate limited
                if httpResponse.statusCode == 429 {
                    logger.warning("AbuseIPDB rate limited")
                    return nil
                }
                if httpResponse.statusCode != 200 {
                    logger.warning("AbuseIPDB returned status \(httpResponse.statusCode) for \(ip)")
                    return nil
                }
            }

            let apiResponse = try JSONDecoder().decode(APIResponse.self, from: responseData)
            let abuseData = apiResponse.data

            let result = AbuseResult(
                ipAddress: abuseData.ipAddress,
                abuseConfidenceScore: abuseData.abuseConfidenceScore,
                countryCode: abuseData.countryCode,
                usageType: abuseData.usageType,
                isp: abuseData.isp,
                domain: abuseData.domain,
                isTor: abuseData.isTor,
                isWhitelisted: abuseData.isWhitelisted,
                totalReports: abuseData.totalReports,
                numDistinctUsers: abuseData.numDistinctUsers,
                lastReportedAt: abuseData.lastReportedAt
            )

            logger.debug("AbuseIPDB lookup success for \(ip): score=\(result.abuseConfidenceScore)")
            return result
        } catch {
            logger.error("AbuseIPDB lookup failed for \(ip): \(error.localizedDescription)")
            return nil
        }
    }

    /// Reset daily request count if we're in a new day
    private func resetDailyCountIfNeeded() {
        let calendar = Calendar.current
        if !calendar.isDateInToday(requestCountResetDate) {
            requestCount = 0
            requestCountResetDate = Date()
            logger.info("AbuseIPDB daily request count reset")
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
