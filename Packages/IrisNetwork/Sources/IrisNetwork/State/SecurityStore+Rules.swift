import Foundation

// MARK: - Rule Management

@MainActor
extension SecurityStore {

    /// Add a new security rule
    public func addRule(_ rule: SecurityRule) async -> Bool {
        guard let proxy = xpcConnection?.remoteObjectProxy as? ProxyXPCProtocol else {
            errorMessage = "Not connected to extension"
            return false
        }

        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(rule) else {
            errorMessage = "Failed to encode rule"
            return false
        }

        return await withCheckedContinuation { continuation in
            proxy.addRule(data) { [weak self] success, error in
                Task { @MainActor in
                    if let error = error {
                        self?.errorMessage = error
                    }
                    if success {
                        await self?.fetchRules()
                    }
                    continuation.resume(returning: success)
                }
            }
        }
    }

    /// Remove a rule by ID
    public func removeRule(_ ruleId: UUID) async -> Bool {
        guard let proxy = xpcConnection?.remoteObjectProxy as? ProxyXPCProtocol else {
            errorMessage = "Not connected to extension"
            return false
        }

        return await withCheckedContinuation { continuation in
            proxy.removeRule(ruleId.uuidString) { [weak self] success in
                Task { @MainActor in
                    if success {
                        await self?.fetchRules()
                    }
                    continuation.resume(returning: success)
                }
            }
        }
    }

    /// Toggle a rule's enabled state
    public func toggleRule(_ ruleId: UUID) async -> Bool {
        guard let proxy = xpcConnection?.remoteObjectProxy as? ProxyXPCProtocol else {
            errorMessage = "Not connected to extension"
            return false
        }

        return await withCheckedContinuation { continuation in
            proxy.toggleRule(ruleId.uuidString) { [weak self] success in
                Task { @MainActor in
                    if success {
                        await self?.fetchRules()
                    }
                    continuation.resume(returning: success)
                }
            }
        }
    }

    // MARK: - Rule Lookups

    /// Get the effective action for a process (first matching process-scope rule)
    public func effectiveAction(for identityKey: String) -> SecurityRule.RuleAction? {
        rules.first {
            $0.isActive && $0.key == identityKey && $0.scope == .process
        }?.action
    }

    // MARK: - Quick Actions

    /// Block all connections from a process (by identity)
    public func blockProcess(
        identityKey: String,
        path: String,
        signingId: String?
    ) async -> Bool {
        // Remove existing process-scope rules for this identity first
        for rule in rules where rule.key == identityKey && rule.scope == .process {
            _ = await removeRule(rule.id)
        }
        let rule = SecurityRule.blockProcess(path: path, signingId: signingId)
        return await addRule(rule)
    }

    /// Allow all connections from a process (by identity)
    public func allowProcess(
        identityKey: String,
        path: String,
        signingId: String?
    ) async -> Bool {
        // Remove existing process-scope rules for this identity first
        for rule in rules where rule.key == identityKey && rule.scope == .process {
            _ = await removeRule(rule.id)
        }
        let rule = SecurityRule.allowProcess(path: path, signingId: signingId)
        return await addRule(rule)
    }

    /// Block a specific endpoint from a process
    public func blockEndpoint(
        processPath: String,
        signingId: String?,
        remoteAddress: String,
        remotePort: UInt16
    ) async -> Bool {
        let rule = SecurityRule(
            processPath: processPath,
            signingId: signingId,
            remoteAddress: remoteAddress,
            remotePort: String(remotePort),
            action: .block,
            scope: .endpoint
        )
        return await addRule(rule)
    }

    /// Allow a specific endpoint from a process
    public func allowEndpoint(
        processPath: String,
        signingId: String?,
        remoteAddress: String,
        remotePort: UInt16
    ) async -> Bool {
        let rule = SecurityRule(
            processPath: processPath,
            signingId: signingId,
            remoteAddress: remoteAddress,
            remotePort: String(remotePort),
            action: .allow,
            scope: .endpoint
        )
        return await addRule(rule)
    }

    /// Update an existing rule via XPC
    public func updateRule(_ rule: SecurityRule) async -> Bool {
        guard let proxy = xpcConnection?.remoteObjectProxy as? ProxyXPCProtocol else {
            errorMessage = "Not connected to extension"
            return false
        }

        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(rule) else {
            errorMessage = "Failed to encode rule"
            return false
        }

        return await withCheckedContinuation { continuation in
            proxy.updateRule(data) { [weak self] success, error in
                Task { @MainActor in
                    if let error { self?.errorMessage = error }
                    if success { await self?.fetchRules() }
                    continuation.resume(returning: success)
                }
            }
        }
    }
}
