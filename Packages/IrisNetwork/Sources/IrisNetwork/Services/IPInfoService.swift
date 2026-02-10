import Foundation
import os.log

/// Fallback geolocation service using ipinfo.io
/// Free tier: 50,000 requests/month (no API key required for basic data)
/// Used when ip-api.com fails or is rate-limited
public actor IPInfoService {

    // MARK: - Singleton

    public static let shared = IPInfoService()

    // MARK: - Types

    /// Response structure from ipinfo.io API
    private struct APIResponse: Codable {
        let ip: String
        let hostname: String?
        let city: String?
        let region: String?
        let country: String?  // 2-letter country code
        let loc: String?      // "latitude,longitude"
        let org: String?      // "AS##### Organization Name"
        let postal: String?
        let timezone: String?
    }

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "IPInfoService")
    private var cache = BoundedCache<GeoIPService.GeoIPResult>(maxSize: 5000, ttl: 3600)
    private let endpoint = "https://ipinfo.io"

    // MARK: - Public Methods

    /// Look up geolocation for a single IP address
    /// - Parameter ip: The IP address to look up
    /// - Returns: GeoIPResult if successful, nil otherwise
    public func lookup(_ ip: String) async -> GeoIPService.GeoIPResult? {
        // Skip private IPs
        guard !EnrichmentHelpers.isPrivateIP(ip) else { return nil }

        // Check cache
        if let cached = cache.get(ip) {
            return cached
        }

        // Fetch from API
        guard let result = await fetchSingle(ip) else { return nil }

        cache.set(ip, value: result)
        return result
    }

    /// Batch lookup geolocation for multiple IP addresses
    public func batchLookup(_ ips: [String]) async -> [String: GeoIPService.GeoIPResult] {
        await EnrichmentHelpers.batchLookup(ips, maxConcurrent: 10, lookup: lookup)
    }

    /// Clear the cache
    public func clearCache() { cache.removeAll() }

    // MARK: - Private Methods

    private func fetchSingle(_ ip: String) async -> GeoIPService.GeoIPResult? {
        guard let url = URL(string: "\(endpoint)/\(ip)/json") else {
            return nil
        }

        do {
            let (data, response) = try await URLSession.shared.data(from: url)

            // Check for rate limiting or errors
            if let httpResponse = response as? HTTPURLResponse {
                if httpResponse.statusCode == 429 {
                    logger.warning("IPInfo rate limited for \(ip)")
                    return nil
                }
                if httpResponse.statusCode != 200 {
                    logger.warning("IPInfo returned status \(httpResponse.statusCode) for \(ip)")
                    return nil
                }
            }

            let apiResponse = try JSONDecoder().decode(APIResponse.self, from: data)

            // Parse the location string "lat,lon"
            var latitude: Double?
            var longitude: Double?
            if let loc = apiResponse.loc {
                let parts = loc.split(separator: ",")
                if parts.count == 2 {
                    latitude = Double(parts[0])
                    longitude = Double(parts[1])
                }
            }

            // Parse ASN from org field (format: "AS##### Organization Name")
            var asn: String?
            var org: String?
            if let orgField = apiResponse.org {
                let parts = orgField.split(separator: " ", maxSplits: 1)
                if parts.count >= 1 {
                    asn = String(parts[0])  // "AS#####"
                }
                if parts.count >= 2 {
                    org = String(parts[1])  // "Organization Name"
                }
            }

            // Convert 2-letter country code to full name
            let countryName = countryName(for: apiResponse.country ?? "")

            return GeoIPService.GeoIPResult(
                country: countryName ?? apiResponse.country ?? "",
                countryCode: apiResponse.country ?? "",
                city: apiResponse.city ?? "",
                latitude: latitude ?? 0,
                longitude: longitude ?? 0,
                isp: nil,
                org: org,
                asn: asn
            )
        } catch {
            logger.error("IPInfo lookup failed for \(ip): \(error.localizedDescription)")
            return nil
        }
    }

    /// Convert 2-letter country code to full country name
    private func countryName(for code: String) -> String? {
        guard !code.isEmpty else { return nil }
        let locale = Locale(identifier: "en_US")
        return locale.localizedString(forRegionCode: code)
    }

}
