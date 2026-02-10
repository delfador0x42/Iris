import Foundation
import os.log

// MARK: - Data Refresh & Enrichment

@MainActor
extension SecurityStore {

    // MARK: - Timer Management

    func startRefreshTimer() {
        stopRefreshTimer()

        refreshTimer = Timer.scheduledTimer(withTimeInterval: refreshInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refreshData()
            }
        }
    }

    func stopRefreshTimer() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    // MARK: - Public Refresh

    /// Standard refresh method - reloads all network data
    public func refresh() async {
        await refreshData()
    }

    /// Refresh all data from the extension
    public func refreshData() async {
        // Use injected data source if available (for testing)
        if let dataSource = dataSource {
            await fetchConnectionsViaDataSource(dataSource)
            await fetchRulesViaDataSource(dataSource)
        } else {
            await fetchConnections()
            await fetchRules()
        }
        lastUpdate = Date()
    }

    // MARK: - Connection Fetching

    func fetchConnectionsViaDataSource(_ dataSource: any NetworkDataSourceProtocol) async {
        do {
            let dataArray = try await dataSource.fetchConnections()
            await processConnectionData(dataArray)
        } catch {
            logger.error("Data source error: \(error.localizedDescription)")
            errorMessage = error.localizedDescription
        }
    }

    func fetchConnections() async {
        guard let proxy = xpcConnection?.remoteObjectProxyWithErrorHandler({ [weak self] error in
            Task { @MainActor in
                self?.logger.error("XPC error: \(error.localizedDescription)")
                self?.errorMessage = error.localizedDescription
            }
        }) as? NetworkXPCProtocol else {
            return
        }

        await withCheckedContinuation { continuation in
            proxy.getConnections { [weak self] dataArray in
                Task { @MainActor in
                    await self?.processConnectionData(dataArray)
                    continuation.resume()
                }
            }
        }
    }

    func processConnectionData(_ dataArray: [Data]) async {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        var newConnections = dataArray.compactMap { data -> NetworkConnection? in
            try? decoder.decode(NetworkConnection.self, from: data)
        }

        // Carry over existing enrichment data for IPs we've already seen
        let existingByIP = Dictionary(grouping: connections) { $0.remoteAddress }
        newConnections = newConnections.map { conn in
            if let existing = existingByIP[conn.remoteAddress]?.first,
               existing.remoteCountry != nil {
                var enriched = conn
                enriched.remoteCountry = existing.remoteCountry
                enriched.remoteCountryCode = existing.remoteCountryCode
                enriched.remoteCity = existing.remoteCity
                enriched.remoteLatitude = existing.remoteLatitude
                enriched.remoteLongitude = existing.remoteLongitude
                enriched.remoteASN = existing.remoteASN
                enriched.remoteOrganization = existing.remoteOrganization
                enriched.remoteOpenPorts = existing.remoteOpenPorts
                enriched.remoteHostnames = existing.remoteHostnames
                enriched.remoteCVEs = existing.remoteCVEs
                enriched.remoteServiceTags = existing.remoteServiceTags
                enriched.remoteCPEs = existing.remoteCPEs
                enriched.abuseScore = existing.abuseScore
                enriched.isKnownScanner = existing.isKnownScanner
                enriched.isBenignService = existing.isBenignService
                enriched.threatClassification = existing.threatClassification
                enriched.isTor = existing.isTor
                enriched.enrichmentSources = existing.enrichmentSources
                return enriched
            }
            return conn
        }

        // Show connections immediately (before enrichment)
        connections = newConnections
        connectionsByProcess = Dictionary(grouping: newConnections) { $0.processId }
        updateDerivedState()

        // Find IPs that still need enrichment
        let enrichedIPs = Set(newConnections.filter { $0.remoteCountry != nil }.map { $0.remoteAddress })
        let needsEnrichment = Set(newConnections.map { $0.remoteAddress })
            .subtracting(enrichedIPs)
            .filter { !$0.isEmpty }

        guard !needsEnrichment.isEmpty else { return }

        // Enrich in background, then merge results
        Task { [weak self] in
            let results = await IPEnrichmentService.shared.batchEnrich(Array(needsEnrichment))
            guard !results.isEmpty else { return }
            await self?.applyEnrichmentResults(results)
        }
    }

    /// Applies enrichment results to current connections without blocking refresh
    func applyEnrichmentResults(_ results: [String: IPEnrichmentService.EnrichmentResult]) {
        connections = connections.map { connection in
            guard let result = results[connection.remoteAddress] else { return connection }
            return Self.applyEnrichment(to: connection, result: result)
        }
        connectionsByProcess = Dictionary(grouping: connections) { $0.processId }
        updateDerivedState()
    }

    static func applyEnrichment(
        to connection: NetworkConnection,
        result: IPEnrichmentService.EnrichmentResult
    ) -> NetworkConnection {
        var enriched = connection
        enriched.remoteCountry = result.country
        enriched.remoteCountryCode = result.countryCode
        enriched.remoteCity = result.city
        // Skip 0,0 coordinates (Null Island) — almost always means "unknown"
        if let lat = result.latitude, let lon = result.longitude,
           !(lat == 0 && lon == 0) {
            enriched.remoteLatitude = lat
            enriched.remoteLongitude = lon
        }
        enriched.remoteASN = result.asn
        enriched.remoteOrganization = result.organization
        enriched.remoteOpenPorts = result.openPorts
        enriched.remoteHostnames = result.hostnames
        enriched.remoteCVEs = result.cves
        enriched.remoteServiceTags = result.serviceTags
        enriched.remoteCPEs = result.cpes
        enriched.abuseScore = result.abuseScore
        enriched.isKnownScanner = result.isKnownScanner
        enriched.isBenignService = result.isBenignService
        enriched.threatClassification = result.threatClassification
        enriched.isTor = result.isTor
        enriched.enrichmentSources = result.sources
        return enriched
    }

    // MARK: - Rules Fetching

    func fetchRulesViaDataSource(_ dataSource: any NetworkDataSourceProtocol) async {
        do {
            let dataArray = try await dataSource.fetchRules()
            processRulesData(dataArray)
        } catch {
            logger.error("Data source error: \(error.localizedDescription)")
            errorMessage = error.localizedDescription
        }
    }

    func fetchRules() async {
        guard let proxy = xpcConnection?.remoteObjectProxyWithErrorHandler({ [weak self] error in
            Task { @MainActor in
                self?.logger.error("XPC error: \(error.localizedDescription)")
            }
        }) as? NetworkXPCProtocol else {
            return
        }

        await withCheckedContinuation { continuation in
            proxy.getRules { [weak self] dataArray in
                Task { @MainActor in
                    self?.processRulesData(dataArray)
                    continuation.resume()
                }
            }
        }
    }

    func processRulesData(_ dataArray: [Data]) {
        let decoder = JSONDecoder()

        rules = dataArray.compactMap { data -> SecurityRule? in
            try? decoder.decode(SecurityRule.self, from: data)
        }
    }
}
