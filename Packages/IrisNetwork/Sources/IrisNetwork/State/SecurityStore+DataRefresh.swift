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

        // Enrich with geolocation data
        newConnections = await enrichWithGeolocation(newConnections)

        connections = newConnections

        // Group by process
        connectionsByProcess = Dictionary(grouping: newConnections) { $0.processId }
    }

    /// Enrich connections with geolocation, security, and threat intelligence data
    /// Uses the unified IPEnrichmentService which provides fallback logic
    func enrichWithGeolocation(_ connections: [NetworkConnection]) async -> [NetworkConnection] {
        // Get unique remote IPs that need lookup
        let uniqueIPs = Set(connections.map { $0.remoteAddress })
            .filter { !$0.isEmpty }

        // Skip if no IPs to look up
        guard !uniqueIPs.isEmpty else { return connections }

        // Use unified enrichment service with fallback logic
        let enrichmentResults = await IPEnrichmentService.shared.batchEnrich(Array(uniqueIPs))

        // Enrich each connection with all data sources
        return connections.map { connection in
            var enriched = connection

            if let result = enrichmentResults[connection.remoteAddress] {
                // Geolocation data
                enriched.remoteCountry = result.country
                enriched.remoteCountryCode = result.countryCode
                enriched.remoteCity = result.city
                enriched.remoteLatitude = result.latitude
                enriched.remoteLongitude = result.longitude
                enriched.remoteASN = result.asn
                enriched.remoteOrganization = result.organization

                // Security data from InternetDB (or reverse DNS for hostnames)
                enriched.remoteOpenPorts = result.openPorts
                enriched.remoteHostnames = result.hostnames
                enriched.remoteCVEs = result.cves
                enriched.remoteServiceTags = result.serviceTags
                enriched.remoteCPEs = result.cpes

                // Threat intelligence data
                enriched.abuseScore = result.abuseScore
                enriched.isKnownScanner = result.isKnownScanner
                enriched.isBenignService = result.isBenignService
                enriched.threatClassification = result.threatClassification
                enriched.isTor = result.isTor
                enriched.enrichmentSources = result.sources
            }

            return enriched
        }
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
