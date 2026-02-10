import Foundation
import Security
import os.log

/// LRU (Least Recently Used) cache for generated leaf certificates.
/// Caches certificates by hostname to avoid regenerating them for every connection.
public final class CertificateCache: @unchecked Sendable {

    // MARK: - Types

    /// A cached certificate entry.
    private struct CacheEntry {
        let privateKey: SecKey
        let certificate: SecCertificate
        let createdAt: Date
        var lastAccess: UInt64
    }

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "CertificateCache")

    /// Maximum number of entries in the cache.
    public let maxCapacity: Int

    /// How long certificates are valid in the cache (default: 1 hour).
    public let ttl: TimeInterval

    /// The cache storage.
    private var cache: [String: CacheEntry] = [:]

    /// Monotonic sequence counter for LRU tracking (O(1) on access).
    private var sequence: UInt64 = 0

    /// Lock for thread-safe access.
    private let lock = NSLock()

    /// Current number of entries.
    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return cache.count
    }

    // MARK: - Initialization

    /// Creates a new certificate cache.
    /// - Parameters:
    ///   - maxCapacity: Maximum number of certificates to cache (default: 1000)
    ///   - ttl: Time-to-live for cached certificates (default: 1 hour)
    public init(maxCapacity: Int = 1000, ttl: TimeInterval = 3600) {
        self.maxCapacity = maxCapacity
        self.ttl = ttl
    }

    // MARK: - Public Methods

    /// Gets a cached certificate for a hostname.
    /// - Parameter hostname: The hostname to look up
    /// - Returns: The cached certificate tuple, or nil if not found/expired
    public func get(hostname: String) -> (privateKey: SecKey, certificate: SecCertificate)? {
        lock.lock()
        defer { lock.unlock() }

        guard var entry = cache[hostname] else {
            return nil
        }

        // Check if expired
        if Date().timeIntervalSince(entry.createdAt) > ttl {
            logger.debug("Cached certificate for \(hostname) expired")
            removeEntryUnsafe(hostname: hostname)
            return nil
        }

        // Update access sequence (O(1))
        sequence += 1
        entry.lastAccess = sequence
        cache[hostname] = entry

        logger.debug("Cache hit for hostname: \(hostname)")
        return (entry.privateKey, entry.certificate)
    }

    /// Caches a certificate for a hostname.
    /// - Parameters:
    ///   - hostname: The hostname
    ///   - certificate: Tuple of (privateKey, certificate) to cache
    public func set(hostname: String, certificate: (privateKey: SecKey, certificate: SecCertificate)) {
        lock.lock()
        defer { lock.unlock() }

        let now = Date()

        // Evict if at capacity
        while cache.count >= maxCapacity {
            evictLRUUnsafe()
        }

        // Add new entry
        sequence += 1
        let entry = CacheEntry(
            privateKey: certificate.privateKey,
            certificate: certificate.certificate,
            createdAt: now,
            lastAccess: sequence
        )

        cache[hostname] = entry

        logger.debug("Cached certificate for hostname: \(hostname), cache size: \(self.cache.count)")
    }

    /// Removes a specific hostname from the cache.
    /// - Parameter hostname: The hostname to remove
    public func remove(hostname: String) {
        lock.lock()
        defer { lock.unlock() }
        removeEntryUnsafe(hostname: hostname)
    }

    /// Clears all entries from the cache.
    public func clear() {
        lock.lock()
        defer { lock.unlock() }

        cache.removeAll()
        sequence = 0

        logger.info("Certificate cache cleared")
    }

    /// Removes expired entries from the cache.
    /// - Returns: Number of entries removed
    @discardableResult
    public func purgeExpired() -> Int {
        lock.lock()
        defer { lock.unlock() }

        let now = Date()
        var removed = 0

        let expiredHostnames = cache.filter { _, entry in
            now.timeIntervalSince(entry.createdAt) > ttl
        }.map { $0.key }

        for hostname in expiredHostnames {
            removeEntryUnsafe(hostname: hostname)
            removed += 1
        }

        if removed > 0 {
            logger.info("Purged \(removed) expired certificates from cache")
        }

        return removed
    }

    /// Gets cache statistics.
    /// - Returns: Statistics about the cache
    public func getStats() -> CacheStats {
        lock.lock()
        defer { lock.unlock() }

        let now = Date()
        var oldestAge: TimeInterval = 0
        var newestAge: TimeInterval = .infinity

        for (_, entry) in cache {
            let age = now.timeIntervalSince(entry.createdAt)
            oldestAge = max(oldestAge, age)
            newestAge = min(newestAge, age)
        }

        return CacheStats(
            count: cache.count,
            capacity: maxCapacity,
            ttl: ttl,
            oldestEntryAge: cache.isEmpty ? 0 : oldestAge,
            newestEntryAge: cache.isEmpty ? 0 : newestAge
        )
    }

    // MARK: - Private Methods

    /// Removes an entry without locking (caller must hold lock).
    private func removeEntryUnsafe(hostname: String) {
        cache.removeValue(forKey: hostname)
    }

    /// Evicts the least recently used entry without locking (caller must hold lock).
    private func evictLRUUnsafe() {
        guard let oldest = cache.min(by: { $0.value.lastAccess < $1.value.lastAccess }) else { return }
        logger.debug("Evicting LRU entry: \(oldest.key)")
        cache.removeValue(forKey: oldest.key)
    }
}

// MARK: - Cache Statistics

/// Statistics about the certificate cache.
public struct CacheStats: Sendable {
    /// Current number of entries.
    public let count: Int

    /// Maximum capacity.
    public let capacity: Int

    /// Time-to-live for entries.
    public let ttl: TimeInterval

    /// Age of the oldest entry in seconds.
    public let oldestEntryAge: TimeInterval

    /// Age of the newest entry in seconds.
    public let newestEntryAge: TimeInterval

    /// Cache utilization as a percentage.
    public var utilization: Double {
        guard capacity > 0 else { return 0 }
        return Double(count) / Double(capacity) * 100
    }
}

// MARK: - CustomStringConvertible

extension CacheStats: CustomStringConvertible {
    public var description: String {
        return """
        CertificateCache Stats:
          Entries: \(count)/\(capacity) (\(String(format: "%.1f", utilization))%)
          TTL: \(Int(ttl))s
          Oldest: \(Int(oldestEntryAge))s
          Newest: \(Int(newestEntryAge))s
        """
    }
}
