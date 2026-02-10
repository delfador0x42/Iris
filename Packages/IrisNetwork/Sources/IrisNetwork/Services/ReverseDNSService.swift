import Foundation
import Darwin
import os.log

/// Service for performing reverse DNS lookups using Darwin's getnameinfo
/// Used as a fallback when Shodan InternetDB has no hostname data for an IP
public actor ReverseDNSService {

    // MARK: - Singleton

    public static let shared = ReverseDNSService()

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "ReverseDNSService")
    private var cache = BoundedCache<String>(maxSize: 5000, ttl: 3600)
    private let maxConcurrent = 10

    // MARK: - Public Methods

    /// Perform reverse DNS lookup for a single IP address
    /// - Parameter ip: The IP address to look up (IPv4 or IPv6)
    /// - Returns: The hostname if found, nil otherwise
    public func lookup(_ ip: String) async -> String? {
        // Check cache first
        if let cached = cache.get(ip) {
            return cached
        }

        // Skip private IPs - they won't have public DNS records
        guard !EnrichmentHelpers.isPrivateIP(ip) else {
            return nil
        }

        // Perform the lookup on a background thread to avoid blocking
        let hostname = await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                let result = self.performReverseDNS(ip)
                continuation.resume(returning: result)
            }
        }

        if let hostname = hostname {
            cache.set(ip, value: hostname)
            logger.debug("Reverse DNS for \(ip): \(hostname)")
        }

        return hostname
    }

    /// Batch lookup hostnames for multiple IP addresses
    public func batchLookup(_ ips: [String]) async -> [String: String] {
        await EnrichmentHelpers.batchLookup(ips, maxConcurrent: maxConcurrent, lookup: lookup)
    }

    /// Clear the cache
    public func clearCache() { cache.removeAll() }

    // MARK: - Private Methods

    /// Perform the actual reverse DNS lookup using Darwin's getnameinfo
    private nonisolated func performReverseDNS(_ ip: String) -> String? {
        // First, convert the IP string to a sockaddr structure using getaddrinfo
        var hints = addrinfo()
        hints.ai_flags = AI_NUMERICHOST  // IP address is numeric, don't do DNS lookup
        hints.ai_family = AF_UNSPEC      // Allow both IPv4 and IPv6
        var result: UnsafeMutablePointer<addrinfo>?

        let status = getaddrinfo(ip, nil, &hints, &result)
        guard status == 0, let info = result else {
            return nil
        }
        defer { freeaddrinfo(result) }

        // Now perform reverse DNS lookup using getnameinfo
        var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let sockaddr = info.pointee.ai_addr
        let socklen = info.pointee.ai_addrlen

        // NI_NAMEREQD: Return error if hostname can't be determined (don't return IP)
        let gniStatus = getnameinfo(
            sockaddr,
            socklen,
            &hostname,
            socklen_t(NI_MAXHOST),
            nil,
            0,
            NI_NAMEREQD
        )

        guard gniStatus == 0 else {
            return nil
        }

        let hostnameString = String(cString: hostname)

        // Sanity check: don't return the IP address as hostname
        if hostnameString == ip {
            return nil
        }

        return hostnameString
    }

}
