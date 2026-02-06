import Foundation
import os.log

/// Unified IP enrichment service that orchestrates multiple data sources
/// Provides fallback logic when primary services fail or have no data
public actor IPEnrichmentService {

    // MARK: - Singleton

    public static let shared = IPEnrichmentService()

    // MARK: - Types

    /// Comprehensive enrichment result combining all data sources
    public struct EnrichmentResult: Sendable {
        // Geolocation (from ip-api, ipinfo)
        public var country: String?
        public var countryCode: String?
        public var city: String?
        public var latitude: Double?
        public var longitude: Double?
        public var asn: String?
        public var organization: String?

        // Hostnames (from InternetDB or reverse DNS)
        public var hostnames: [String]?

        // Security (from InternetDB)
        public var openPorts: [UInt16]?
        public var cves: [String]?
        public var serviceTags: [String]?
        public var cpes: [String]?

        // Threat intelligence (from GreyNoise, AbuseIPDB)
        public var abuseScore: Int?
        public var isKnownScanner: Bool?
        public var isBenignService: Bool?
        public var threatClassification: String?
        public var isTor: Bool?

        // Metadata
        public var sources: [String]  // Which services contributed data

        public init(
            country: String? = nil,
            countryCode: String? = nil,
            city: String? = nil,
            latitude: Double? = nil,
            longitude: Double? = nil,
            asn: String? = nil,
            organization: String? = nil,
            hostnames: [String]? = nil,
            openPorts: [UInt16]? = nil,
            cves: [String]? = nil,
            serviceTags: [String]? = nil,
            cpes: [String]? = nil,
            abuseScore: Int? = nil,
            isKnownScanner: Bool? = nil,
            isBenignService: Bool? = nil,
            threatClassification: String? = nil,
            isTor: Bool? = nil,
            sources: [String] = []
        ) {
            self.country = country
            self.countryCode = countryCode
            self.city = city
            self.latitude = latitude
            self.longitude = longitude
            self.asn = asn
            self.organization = organization
            self.hostnames = hostnames
            self.openPorts = openPorts
            self.cves = cves
            self.serviceTags = serviceTags
            self.cpes = cpes
            self.abuseScore = abuseScore
            self.isKnownScanner = isKnownScanner
            self.isBenignService = isBenignService
            self.threatClassification = threatClassification
            self.isTor = isTor
            self.sources = sources
        }
    }

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "IPEnrichmentService")
    private var cache: [String: EnrichmentResult] = [:]

    // MARK: - Public Methods

    /// Enrich a single IP with all available data sources
    /// - Parameter ip: The IP address to enrich
    /// - Returns: Comprehensive enrichment result
    public func enrich(_ ip: String) async -> EnrichmentResult {
        // Check cache first
        if let cached = cache[ip] {
            return cached
        }

        // Skip private IPs entirely
        guard !isPrivateIP(ip) else {
            return EnrichmentResult(sources: [])
        }

        var result = EnrichmentResult(sources: [])

        // Run all enrichment tasks in parallel
        async let geoTask = enrichGeolocation(ip)
        async let securityTask = InternetDBService.shared.lookup(ip)
        async let greynoiseTask = enrichGreyNoise(ip)
        async let abuseTask = enrichAbuseIPDB(ip)

        // Await all in parallel
        let (geo, security, greynoise, abuse) = await (geoTask, securityTask, greynoiseTask, abuseTask)

        // Apply geolocation data
        if let geo = geo {
            result.country = geo.country
            result.countryCode = geo.countryCode
            result.city = geo.city
            result.latitude = geo.latitude
            result.longitude = geo.longitude
            result.asn = geo.asn
            result.organization = geo.org
            result.sources.append("geo")
        }

        // Apply security data from InternetDB
        if let security = security {
            result.openPorts = security.portsAsUInt16
            result.hostnames = security.hostnames
            result.cves = security.vulns
            result.serviceTags = security.tags
            result.cpes = security.cpes
            result.sources.append("shodan")
        }

        // Fallback: If no hostnames from InternetDB, try reverse DNS
        if result.hostnames == nil || result.hostnames!.isEmpty {
            if let hostname = await ReverseDNSService.shared.lookup(ip) {
                result.hostnames = [hostname]
                result.sources.append("rdns")
            }
        }

        // Apply GreyNoise threat intelligence
        if let greynoise = greynoise {
            result.isKnownScanner = greynoise.noise
            result.isBenignService = greynoise.riot
            result.threatClassification = greynoise.classification
            result.sources.append("greynoise")
        }

        // Apply AbuseIPDB data
        if let abuse = abuse {
            result.abuseScore = abuse.abuseConfidenceScore
            result.isTor = abuse.isTor
            result.sources.append("abuseipdb")

            // If we didn't get org from geolocation, try from AbuseIPDB
            if result.organization == nil {
                result.organization = abuse.isp
            }
        }

        // Cache the result
        cache[ip] = result

        logger.debug("Enriched \(ip) with sources: \(result.sources.joined(separator: ", "))")

        return result
    }

    /// Batch enrich multiple IPs concurrently
    /// - Parameter ips: Array of IP addresses to enrich
    /// - Returns: Dictionary mapping IP addresses to their enrichment results
    public func batchEnrich(_ ips: [String]) async -> [String: EnrichmentResult] {
        // Filter out private IPs
        let publicIPs = ips.filter { !isPrivateIP($0) }

        guard !publicIPs.isEmpty else { return [:] }

        // Collect results - some may be cached
        var results: [String: EnrichmentResult] = [:]
        var uncachedIPs: [String] = []

        for ip in publicIPs {
            if let cached = cache[ip] {
                results[ip] = cached
            } else {
                uncachedIPs.append(ip)
            }
        }

        guard !uncachedIPs.isEmpty else { return results }

        // Fetch uncached IPs concurrently
        // Limit concurrency to avoid overwhelming APIs
        let maxConcurrent = 20

        await withTaskGroup(of: (String, EnrichmentResult).self) { group in
            for ip in uncachedIPs.prefix(maxConcurrent) {
                group.addTask {
                    let result = await self.enrich(ip)
                    return (ip, result)
                }
            }

            for await (ip, result) in group {
                results[ip] = result
            }
        }

        logger.info("Batch enriched \(results.count) IPs (\(uncachedIPs.count) new)")

        return results
    }

    /// Clear all caches (individual services and unified cache)
    public func clearAllCaches() async {
        cache.removeAll()
        await GeoIPService.shared.clearCache()
        await IPInfoService.shared.clearCache()
        await InternetDBService.shared.clearCache()
        await ReverseDNSService.shared.clearCache()
        await GreyNoiseService.shared.clearCache()
        await AbuseIPDBService.shared.clearCache()
        logger.info("All enrichment caches cleared")
    }

    // MARK: - Private Methods

    /// Enrich geolocation with fallback chain
    private func enrichGeolocation(_ ip: String) async -> GeoIPService.GeoIPResult? {
        // Try ip-api first (fast, high rate limit)
        if let result = await GeoIPService.shared.lookup(ip) {
            return result
        }

        // Fallback to ipinfo.io
        if let result = await IPInfoService.shared.lookup(ip) {
            return result
        }

        return nil
    }

    /// Enrich with GreyNoise (only if available)
    private func enrichGreyNoise(_ ip: String) async -> GreyNoiseService.GreyNoiseResult? {
        guard await GreyNoiseService.shared.isAvailable() else {
            return nil
        }
        return await GreyNoiseService.shared.lookup(ip)
    }

    /// Enrich with AbuseIPDB (only if configured)
    private func enrichAbuseIPDB(_ ip: String) async -> AbuseIPDBService.AbuseResult? {
        guard await AbuseIPDBService.shared.isAvailable() else {
            return nil
        }
        return await AbuseIPDBService.shared.lookup(ip)
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
