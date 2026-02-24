//
//  DNSStore.swift
//  IrisDNS
//
//  Main state store for DNS monitoring and encrypted DNS management.
//

import Foundation
import SwiftUI
import os.log

/// Main store for DNS state, query monitoring, and DoH configuration.
@MainActor @Observable
public final class DNSStore {

    // MARK: - State

    /// Whether encrypted DNS is enabled.
    public internal(set) var isEnabled: Bool = false

    /// Whether the DNS extension is connected and active.
    public internal(set) var isActive: Bool = false

    /// All captured DNS queries.
    public internal(set) var queries: [DNSQueryRecord] = [] { didSet { updateFilteredQueries() } }

    /// Current search/filter query (debounced via Task).
    public var searchQuery: String = "" { didSet { debouncedSearch() } }

    /// Active record type filter.
    public var typeFilter: String? { didSet { updateFilteredQueries() } }

    /// Whether to show only blocked queries.
    public var showBlockedOnly: Bool = false { didSet { updateFilteredQueries() } }

    /// Derived: filtered queries (updated when queries or filters change).
    public internal(set) var filteredQueries: [DNSQueryRecord] = []

    /// Derived: unique record types in captured queries.
    public internal(set) var availableTypes: [String] = []

    /// Derived: top queried domains.
    public internal(set) var topDomains: [(domain: String, count: Int)] = []

    /// Currently selected query for detail view.
    public var selectedQuery: DNSQueryRecord?

    /// Currently loading.
    public internal(set) var isLoading: Bool = false

    /// Connection error message.
    public internal(set) var errorMessage: String?

    /// Current DoH server name.
    public internal(set) var serverName: String = "Cloudflare"

    /// Statistics.
    public internal(set) var totalQueries: Int = 0
    public internal(set) var averageLatencyMs: Double = 0
    public internal(set) var successRate: Double = 1.0

    // MARK: - Properties

    let logger = Logger(subsystem: "com.wudan.iris", category: "DNSStore")
    var xpcConnection: NSXPCConnection?
    var refreshTimer: Timer?
    private var searchTask: Task<Void, Never>?

    /// Last seen sequence number from the DNS extension.
    /// Used for delta XPC protocol — only fetch queries newer than this.
    var lastSeenSequence: UInt64 = 0

    /// Pre-computed lowercase search fields, keyed by query UUID.
    /// Built once when queries change (in didSet), not per-keystroke.
    var searchIndex: [UUID: SearchEntry] = [:]

    // MARK: - Singleton

    public static let shared = DNSStore()

    // MARK: - Initialization

    public init() {}

    private func debouncedSearch() {
        searchTask?.cancel()
        searchTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard !Task.isCancelled else { return }
            self?.updateFilteredQueries()
        }
    }

    // Singleton — never deallocated, no deinit needed
}
