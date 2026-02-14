import Foundation
import NetworkExtension
import os.log

/// Manages the transparent proxy configuration.
/// NE configs persist across app restarts (stored by neagent, not in app sandbox).
/// On startup, call ensureRunning() — it reconnects existing configs without recreating.
/// Only enableProxy() creates/replaces configs (called once during extension installation).
@MainActor
public struct TransparentProxyManager {

  private static let logger = Logger(
    subsystem: "com.wudan.iris", category: "TransparentProxyManager")
  private static let providerBundleID = "com.wudan.iris.proxy.extension"

  // MARK: - Startup

  /// Ensure the proxy tunnel is running. Call on every app launch.
  /// Does NOT clean/recreate configs — just reconnects if the tunnel stopped (reboot, crash).
  /// Returns true if the proxy is connected or connecting.
  @discardableResult
  public static func ensureRunning() async -> Bool {
    do {
      let managers = try await NETransparentProxyManager.loadAllFromPreferences()
      logger.error("[DIAG] ensureRunning: found \(managers.count) manager(s)")
      guard
        let manager = managers.first(where: { m in
          guard let proto = m.protocolConfiguration as? NETunnelProviderProtocol else {
            return false
          }
          return proto.providerBundleIdentifier == providerBundleID
        })
      else {
        logger.error("[DIAG] No proxy config exists — calling enableProxy()")
        return await enableProxy()
      }

      logger.error(
        "[DIAG] Found config, isEnabled=\(manager.isEnabled), status=\(manager.connection.status.rawValue)"
      )
      guard manager.isEnabled else {
        logger.error("[DIAG] Proxy config disabled — re-enabling")
        return await enableProxy()
      }

      switch manager.connection.status {
      case .connected:
        logger.error("[DIAG] Proxy tunnel already connected")
        return true
      case .connecting, .reasserting:
        logger.error("[DIAG] Proxy tunnel connecting...")
        return true
      case .disconnected, .invalid:
        logger.error("[DIAG] Proxy tunnel disconnected — restarting")
        try await manager.loadFromPreferences()
        try manager.connection.startVPNTunnel()
        logger.error("[DIAG] Proxy tunnel restart initiated")
        return true
      case .disconnecting:
        try? await Task.sleep(nanoseconds: 500_000_000)
        try manager.connection.startVPNTunnel()
        return true
      @unknown default:
        logger.error("[DIAG] Proxy tunnel unknown status: \(manager.connection.status.rawValue)")
        return false
      }
    } catch {
      logger.error("[DIAG] ensureRunning failed: \(error.localizedDescription)")
      return false
    }
  }

  // MARK: - Proxy Control

  /// Create or replace the proxy config and start the tunnel.
  /// Called once during extension installation, or to force-recreate after errors.
  @discardableResult
  public static func enableProxy() async -> Bool {
    logger.error("[DIAG] enableProxy() called")

    do {
      let manager = try await loadOrCreateManager()
      logger.error("[DIAG] enableProxy: got manager")

      let proto = NETunnelProviderProtocol()
      proto.providerBundleIdentifier = providerBundleID
      proto.serverAddress = "localhost"

      manager.protocolConfiguration = proto
      manager.localizedDescription = "Iris HTTPS Proxy"
      manager.isEnabled = true

      try await manager.saveToPreferences()
      logger.error("[DIAG] enableProxy: saved to preferences")
      try await manager.loadFromPreferences()
      logger.error("[DIAG] enableProxy: reloaded, status=\(manager.connection.status.rawValue)")

      if manager.connection.status != .connected {
        try manager.connection.startVPNTunnel()
        logger.error("[DIAG] enableProxy: startVPNTunnel called")
      }

      logger.error("[DIAG] enableProxy: success")
      return true

    } catch {
      logger.error("[DIAG] enableProxy FAILED: \(error.localizedDescription)")
      return false
    }
  }

  /// Disable the transparent proxy.
  @discardableResult
  public static func disableProxy() async -> Bool {
    logger.info("Disabling transparent proxy...")

    do {
      let managers = try await NETransparentProxyManager.loadAllFromPreferences()
      guard
        let manager = managers.first(where: { m in
          guard let proto = m.protocolConfiguration as? NETunnelProviderProtocol else {
            return false
          }
          return proto.providerBundleIdentifier == providerBundleID
        })
      else {
        logger.info("No proxy config to disable")
        return true
      }
      manager.isEnabled = false
      try await manager.saveToPreferences()
      logger.info("Transparent proxy disabled")
      return true
    } catch {
      logger.error("Failed to disable transparent proxy: \(error.localizedDescription)")
      return false
    }
  }

  /// Remove all transparent proxy configurations. Use for clean reinstall only.
  public static func cleanConfiguration() async {
    logger.info("Cleaning transparent proxy configurations...")

    do {
      let managers = try await NETransparentProxyManager.loadAllFromPreferences()
      for manager in managers {
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
          proto.providerBundleIdentifier == providerBundleID
        {
          try await manager.removeFromPreferences()
          logger.info("Removed proxy config: \(manager.localizedDescription ?? "unnamed")")
        }
      }
    } catch {
      logger.error("Failed to clean proxy configuration: \(error.localizedDescription)")
    }
  }

  // MARK: - Status Checking

  /// Check if the transparent proxy is configured and its current state.
  public static func checkStatus() async -> (isConfigured: Bool, isEnabled: Bool) {
    do {
      let managers = try await NETransparentProxyManager.loadAllFromPreferences()
      for manager in managers {
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
          proto.providerBundleIdentifier == providerBundleID
        {
          return (true, manager.isEnabled)
        }
      }
      return (false, false)
    } catch {
      logger.error("Failed to check proxy status: \(error.localizedDescription)")
      return (false, false)
    }
  }

  // MARK: - Private

  /// Load existing manager or create a new one.
  private static func loadOrCreateManager() async throws -> NETransparentProxyManager {
    let managers = try await NETransparentProxyManager.loadAllFromPreferences()
    if let existing = managers.first(where: { m in
      guard let proto = m.protocolConfiguration as? NETunnelProviderProtocol else { return false }
      return proto.providerBundleIdentifier == providerBundleID
    }) {
      return existing
    }
    return NETransparentProxyManager()
  }
}
