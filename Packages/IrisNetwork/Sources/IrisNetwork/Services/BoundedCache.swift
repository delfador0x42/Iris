//
//  BoundedCache.swift
//  IrisNetwork
//
//  LRU cache with size limit and TTL eviction.
//  Used by all enrichment services to prevent unbounded memory growth.
//

import Foundation

/// Bounded cache with TTL and LRU eviction.
/// Designed for use inside actors (no internal locking needed).
/// Marked nonisolated to avoid actor-isolation inference in Swift 6.
nonisolated struct BoundedCache<Value> {
    private var entries: [String: Entry] = [:]
    private var accessOrder: [String] = []  // Most recent at end
    let maxSize: Int
    let ttl: TimeInterval

    struct Entry {
        let value: Value
        let insertedAt: Date
    }

    init(maxSize: Int = 5000, ttl: TimeInterval = 3600) {
        self.maxSize = maxSize
        self.ttl = ttl
    }

    mutating func get(_ key: String) -> Value? {
        guard let entry = entries[key] else { return nil }
        // Check TTL
        if Date().timeIntervalSince(entry.insertedAt) > ttl {
            entries.removeValue(forKey: key)
            accessOrder.removeAll { $0 == key }
            return nil
        }
        // Move to end (most recently accessed)
        accessOrder.removeAll { $0 == key }
        accessOrder.append(key)
        return entry.value
    }

    mutating func set(_ key: String, value: Value) {
        // Remove existing entry if present
        if entries[key] != nil {
            accessOrder.removeAll { $0 == key }
        }
        // Evict LRU if at capacity
        while entries.count >= maxSize, let oldest = accessOrder.first {
            entries.removeValue(forKey: oldest)
            accessOrder.removeFirst()
        }
        entries[key] = Entry(value: value, insertedAt: Date())
        accessOrder.append(key)
    }

    /// Check if key exists (even if expired -- for negative caching)
    func contains(_ key: String) -> Bool {
        entries[key] != nil
    }

    mutating func removeAll() {
        entries.removeAll()
        accessOrder.removeAll()
    }

    var count: Int { entries.count }
}
