import Foundation

/// Shared helpers for IP enrichment services.
/// Eliminates ~210 lines of duplicated isPrivateIP() across 7 services.
public enum EnrichmentHelpers {
    /// Check if an IP address is private/reserved (not routable on public internet)
    public static func isPrivateIP(_ ip: String) -> Bool {
        // IPv4 private ranges
        if ip.hasPrefix("10.") || ip.hasPrefix("192.168.") ||
           ip.hasPrefix("127.") || ip.hasPrefix("0.") || ip == "localhost" {
            return true
        }
        // 172.16.0.0/12
        if ip.hasPrefix("172.") {
            let parts = ip.split(separator: ".")
            if parts.count >= 2, let second = Int(parts[1]),
               second >= 16, second <= 31 {
                return true
            }
        }
        // IPv6 private/link-local
        if ip == "::1" || ip.lowercased().hasPrefix("fe80:") ||
           ip.lowercased().hasPrefix("fc") || ip.lowercased().hasPrefix("fd") {
            return true
        }
        // IPv4-mapped IPv6 (::ffff:192.168.x.x)
        let lower = ip.lowercased()
        if lower.hasPrefix("::ffff:") {
            let mapped = String(lower.dropFirst(7))
            return isPrivateIP(mapped)
        }
        return false
    }

    /// Filter an IP list to only public (non-private) addresses
    public static func filterPublic(_ ips: [String]) -> [String] {
        ips.filter { !isPrivateIP($0) }
    }

    /// Standard batch lookup: filter private, fetch via TaskGroup with concurrency limit.
    /// Each service's `lookup()` already handles cache, so we just call it for every IP.
    /// Cache hits are O(1) dict lookups — no wasted API calls.
    public static func batchLookup<R: Sendable>(
        _ ips: [String],
        maxConcurrent: Int,
        lookup: @escaping @Sendable (String) async -> R?
    ) async -> [String: R] {
        let publicIPs = filterPublic(ips)
        guard !publicIPs.isEmpty else { return [:] }

        var results: [String: R] = [:]

        await withTaskGroup(of: (String, R?).self) { group in
            for ip in publicIPs.prefix(maxConcurrent) {
                group.addTask { (ip, await lookup(ip)) }
            }
            for await (ip, result) in group {
                if let result = result { results[ip] = result }
            }
        }
        return results
    }
}
