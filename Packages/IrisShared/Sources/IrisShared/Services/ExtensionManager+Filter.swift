import AppKit
import Foundation
import NetworkExtension
import os.log

// MARK: - Network Filter, DNS Proxy, Full Disk Access & System Settings

@MainActor
extension ExtensionManager {

  // MARK: - Network Filter Control

  /// Enable the network filter
  public func enableFilter() async {
    filterState = .configuring
    filterState = await NetworkFilterManager.enableFilter()
    if filterState != .enabled {
      lastError = "Failed to enable network filter"
    }
  }

  /// Disable the network filter
  public func disableFilter() async {
    filterState = .configuring
    filterState = await NetworkFilterManager.disableFilter()
  }

  /// Completely remove the network filter configuration
  public func cleanNetworkFilterConfiguration() async {
    await NetworkFilterManager.cleanConfiguration()
    filterState = .disabled
  }

  // MARK: - DNS Proxy Control

  /// Enable the DNS proxy via NEDNSProxyManager
  public func enableDNSProxy() async {
    let success = await DNSProxyManager.enableDNSProxy()
    if !success {
      lastError = "Failed to enable DNS proxy"
    }
  }

  /// Disable the DNS proxy
  public func disableDNSProxy() async {
    await DNSProxyManager.disableDNSProxy()
  }

  /// Check DNS proxy status
  public func checkDNSProxyStatus() async -> (isConfigured: Bool, isEnabled: Bool) {
    return await DNSProxyManager.checkStatus()
  }

  // MARK: - Transparent Proxy Control

  /// Enable the transparent proxy via NETransparentProxyManager
  public func enableTransparentProxy() async {
    let success = await TransparentProxyManager.enableProxy()
    if !success {
      lastError = "Failed to enable transparent proxy"
    }
  }

  /// Disable the transparent proxy
  public func disableTransparentProxy() async {
    await TransparentProxyManager.disableProxy()
  }

  /// Completely remove the transparent proxy configuration
  public func cleanTransparentProxyConfiguration() async {
    await TransparentProxyManager.cleanConfiguration()
  }

  // MARK: - Full Disk Access

  /// Check if Full Disk Access is granted (required for Endpoint Security)
  public func checkFullDiskAccess() async {
    let testPath = "/Library/Application Support/com.apple.TCC/TCC.db"
    let hasAccess = (try? Data(contentsOf: URL(fileURLWithPath: testPath))) != nil
    hasFullDiskAccess = hasAccess
    logger.info("Full Disk Access: \(hasAccess ? "Granted" : "Not granted")")
  }

  // MARK: - System Settings

  /// Open System Settings to Privacy & Security (Extensions)
  public func openSystemSettings() {
    if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy") {
      NSWorkspace.shared.open(url)
    }
  }

  /// Open System Settings to Full Disk Access
  public func openFullDiskAccessSettings() {
    if let url = URL(
      string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
    {
      NSWorkspace.shared.open(url)
    }
  }
}
