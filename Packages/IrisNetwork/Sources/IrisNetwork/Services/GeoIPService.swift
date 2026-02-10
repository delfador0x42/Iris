import Foundation
import os.log

/// Service for looking up IP geolocation data
/// Uses ip-api.com free API (no key required, 45 requests/minute, batch up to 100)
public actor GeoIPService {

    // MARK: - Singleton

    public static let shared = GeoIPService()

    // MARK: - Types

    public struct GeoIPResult: Sendable, Codable {
        public let country: String
        public let countryCode: String
        public let city: String
        public let latitude: Double
        public let longitude: Double
        public let isp: String?
        public let org: String?
        public let asn: String?

        enum CodingKeys: String, CodingKey {
            case country
            case countryCode
            case city
            case latitude = "lat"
            case longitude = "lon"
            case isp
            case org
            case asn = "as"
        }
    }

    // API response structure for ip-api.com
    private struct APIResponse: Codable {
        let status: String
        let country: String?
        let countryCode: String?
        let city: String?
        let lat: Double?
        let lon: Double?
        let isp: String?
        let org: String?
        let `as`: String?
        let query: String
    }

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "GeoIPService")
    private var cache = BoundedCache<GeoIPResult>(maxSize: 5000, ttl: 3600)
    private let batchEndpoint = "http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,isp,org,as,query"
    private let singleEndpoint = "http://ip-api.com/json/"

    // MARK: - Public Methods

    /// Look up geolocation for a single IP address
    public func lookup(_ ipAddress: String) async -> GeoIPResult? {
        // Skip private/local IPs
        guard !EnrichmentHelpers.isPrivateIP(ipAddress) else { return nil }

        // Check cache
        if let cached = cache.get(ipAddress) {
            return cached
        }

        // Fetch from API with retry logic
        guard let result = await fetchWithRetry(ipAddress) else { return nil }

        cache.set(ipAddress, value: result)
        return result
    }

    /// Fetch with retry logic and exponential backoff
    private func fetchWithRetry(_ ip: String, retries: Int = 2) async -> GeoIPResult? {
        for attempt in 0..<retries {
            if let result = await fetchSingle(ip) {
                return result
            }
            // Exponential backoff: 100ms, 200ms
            if attempt < retries - 1 {
                try? await Task.sleep(nanoseconds: UInt64(100_000_000 * (1 << attempt)))
            }
        }
        return nil
    }

    /// Look up geolocation for multiple IP addresses (batch)
    /// Returns dictionary mapping IP -> GeoIPResult
    public func batchLookup(_ ipAddresses: [String]) async -> [String: GeoIPResult] {
        // Filter out private IPs and already-cached
        let publicIPs = EnrichmentHelpers.filterPublic(ipAddresses)
        let uncachedIPs = publicIPs.filter { cache.get($0) == nil }

        // Start with cached results
        var results: [String: GeoIPResult] = [:]
        for ip in publicIPs {
            if let cached = cache.get(ip) {
                results[ip] = cached
            }
        }

        // Nothing to fetch
        guard !uncachedIPs.isEmpty else { return results }

        // Batch fetch (max 100 per request)
        for chunk in uncachedIPs.chunked(into: 100) {
            let newResults = await fetchBatch(chunk)
            for (ip, result) in newResults {
                cache.set(ip, value: result)
                results[ip] = result
            }
        }

        return results
    }

    /// Clear the cache
    public func clearCache() {
        cache.removeAll()
    }

    // MARK: - Private Methods

    private func fetchSingle(_ ip: String) async -> GeoIPResult? {
        guard let url = URL(string: "\(singleEndpoint)\(ip)?fields=status,country,countryCode,city,lat,lon,isp,org,as") else {
            return nil
        }

        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            let response = try JSONDecoder().decode(APIResponse.self, from: data)

            guard response.status == "success",
                  let country = response.country,
                  let countryCode = response.countryCode,
                  let lat = response.lat,
                  let lon = response.lon else {
                return nil
            }

            return GeoIPResult(
                country: country,
                countryCode: countryCode,
                city: response.city ?? "",
                latitude: lat,
                longitude: lon,
                isp: response.isp,
                org: response.org,
                asn: response.as
            )
        } catch {
            logger.error("Failed to fetch geolocation for \(ip): \(error.localizedDescription)")
            return nil
        }
    }

    private func fetchBatch(_ ips: [String]) async -> [String: GeoIPResult] {
        guard let url = URL(string: batchEndpoint) else { return [:] }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        do {
            request.httpBody = try JSONEncoder().encode(ips)
            let (data, _) = try await URLSession.shared.data(for: request)
            let responses = try JSONDecoder().decode([APIResponse].self, from: data)

            var results: [String: GeoIPResult] = [:]

            for response in responses {
                guard response.status == "success",
                      let country = response.country,
                      let countryCode = response.countryCode,
                      let lat = response.lat,
                      let lon = response.lon else {
                    continue
                }

                results[response.query] = GeoIPResult(
                    country: country,
                    countryCode: countryCode,
                    city: response.city ?? "",
                    latitude: lat,
                    longitude: lon,
                    isp: response.isp,
                    org: response.org,
                    asn: response.as
                )
            }

            logger.info("Batch lookup completed: \(results.count)/\(ips.count) IPs resolved")
            return results
        } catch {
            logger.error("Batch geolocation lookup failed: \(error.localizedDescription)")
            return [:]
        }
    }

}

// MARK: - Array Extension for Chunking

extension Array {
    func chunked(into size: Int) -> [[Element]] {
        stride(from: 0, to: count, by: size).map {
            Array(self[$0..<Swift.min($0 + size, count)])
        }
    }
}
