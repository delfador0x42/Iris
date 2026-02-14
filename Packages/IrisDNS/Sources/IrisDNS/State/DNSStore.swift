//
//  DNSStore.swift
//  IrisDNS
//
//  Main state store for DNS monitoring and encrypted DNS management.
//

import Foundation
import SwiftUI
import Combine
import os.log

/// Main store for DNS state, query monitoring, and DoH configuration.
@MainActor
public final class DNSStore: ObservableObject {

    // MARK: - Published State

    /// Whether encrypted DNS is enabled.
    @Published public internal(set) var isEnabled: Bool = false

    /// Whether the DNS extension is connected and active.
    @Published public internal(set) var isActive: Bool = false

    /// All captured DNS queries.
    @Published public internal(set) var queries: [DNSQueryRecord] = [] { didSet { updateFilteredQueries() } }

    /// Current search/filter query (debounced via Combine).
    @Published public var searchQuery: String = ""

    /// Active record type filter.
    @Published public var typeFilter: String? { didSet { updateFilteredQueries() } }

    /// Whether to show only blocked queries.
    @Published public var showBlockedOnly: Bool = false { didSet { updateFilteredQueries() } }

    /// Derived: filtered queries (updated when queries or filters change).
    @Published public internal(set) var filteredQueries: [DNSQueryRecord] = []

    /// Derived: unique record types in captured queries.
    @Published public internal(set) var availableTypes: [String] = []

    /// Derived: top queried domains.
    @Published public internal(set) var topDomains: [(domain: String, count: Int)] = []

    /// Currently selected query for detail view.
    @Published public var selectedQuery: DNSQueryRecord?

    /// Currently loading.
    @Published public internal(set) var isLoading: Bool = false

    /// Connection error message.
    @Published public internal(set) var errorMessage: String?

    /// Current DoH server name.
    @Published public internal(set) var serverName: String = "Cloudflare"

    /// Statistics.
    @Published public internal(set) var totalQueries: Int = 0
    @Published public internal(set) var averageLatencyMs: Double = 0
    @Published public internal(set) var successRate: Double = 1.0

    // MARK: - Properties

    let logger = Logger(subsystem: "com.wudan.iris", category: "DNSStore")
    var xpcConnection: NSXPCConnection?
    var refreshTimer: Timer?
    var cancellables = Set<AnyCancellable>()

    /// Last seen sequence number from the DNS extension.
    /// Used for delta XPC protocol — only fetch queries newer than this.
    var lastSeenSequence: UInt64 = 0

    /// Pre-computed lowercase search fields, keyed by query UUID.
    /// Built once when queries change (in didSet), not per-keystroke.
    var searchIndex: [UUID: SearchEntry] = [:]

    // MARK: - Singleton

    public static let shared = DNSStore()

    // MARK: - Initialization

    public init() {
        setupSearchDebounce()
    }

    deinit {
        refreshTimer?.invalidate()
        xpcConnection?.invalidate()
    }
}
