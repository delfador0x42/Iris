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
        guard !isPrivateIP(ip) else {
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
    /// - Parameter ips: Array of IP addresses to look up
    /// - Returns: Dictionary mapping IP addresses to their hostnames
    public func batchLookup(_ ips: [String]) async -> [String: String] {
        // Filter out private IPs and already-cached
        let publicIPs = ips.filter { !isPrivateIP($0) }
        var uncachedIPs: [String] = []
        var results: [String: String] = [:]

        // Start with cached results
        for ip in publicIPs {
            if let cached = cache.get(ip) {
                results[ip] = cached
            } else {
                uncachedIPs.append(ip)
            }
        }

        guard !uncachedIPs.isEmpty else { return results }

        // Fetch uncached IPs concurrently with limit
        await withTaskGroup(of: (String, String?).self) { group in
            for ip in uncachedIPs.prefix(maxConcurrent) {
                group.addTask {
                    let hostname = await self.lookup(ip)
                    return (ip, hostname)
                }
            }

            for await (ip, hostname) in group {
                if let hostname = hostname {
                    results[ip] = hostname
                }
            }
        }

        let successCount = results.count - (publicIPs.count - uncachedIPs.count)
        if successCount > 0 {
            logger.info("Reverse DNS batch: \(successCount)/\(uncachedIPs.count) IPs resolved")
        }

        return results
    }

    /// Clear the cache
    public func clearCache() {
        cache.removeAll()
        logger.info("Reverse DNS cache cleared")
    }

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

    /// Check if an IP address is private/local (not routable on the internet)
    private nonisolated func isPrivateIP(_ ip: String) -> Bool {
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
