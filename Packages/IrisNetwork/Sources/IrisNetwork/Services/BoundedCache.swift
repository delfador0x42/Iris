//
//  BoundedCache.swift
//  IrisNetwork
//
//  LRU cache with size limit and TTL eviction.
//  Used by all enrichment services to prevent unbounded memory growth.
//

import Foundation

/// Bounded cache with TTL and LRU eviction.
/// Uses sequence counters for O(1) get/set (eviction is O(n) but rare).
/// Designed for use inside actors (no internal locking needed).
/// Marked nonisolated to avoid actor-isolation inference in Swift 6.
nonisolated struct BoundedCache<Value> {
    private var entries: [String: Entry] = [:]
    private var sequence: UInt64 = 0
    let maxSize: Int
    let ttl: TimeInterval

    struct Entry {
        let value: Value
        let insertedAt: Date
        var lastAccess: UInt64
    }

    init(maxSize: Int = 5000, ttl: TimeInterval = 3600) {
        self.maxSize = maxSize
        self.ttl = ttl
    }

    mutating func get(_ key: String) -> Value? {
        guard var entry = entries[key] else { return nil }
        if Date().timeIntervalSince(entry.insertedAt) >= ttl {
            entries.removeValue(forKey: key)
            return nil
        }
        sequence += 1
        entry.lastAccess = sequence
        entries[key] = entry
        return entry.value
    }

    mutating func set(_ key: String, value: Value) {
        // Evict LRU if at capacity and this is a new key
        if entries[key] == nil, entries.count >= maxSize {
            if let oldest = entries.min(by: { $0.value.lastAccess < $1.value.lastAccess }) {
                entries.removeValue(forKey: oldest.key)
            }
        }
        sequence += 1
        entries[key] = Entry(value: value, insertedAt: Date(), lastAccess: sequence)
    }

    /// Check if key exists (even if expired -- for negative caching)
    func contains(_ key: String) -> Bool {
        entries[key] != nil
    }

    mutating func removeAll() {
        entries.removeAll()
        sequence = 0
    }

    var count: Int { entries.count }
}
