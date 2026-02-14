import Foundation
import NetworkExtension
import os.log

/// Manages the network filter configuration
@MainActor
public struct NetworkFilterManager {

  private static let logger = Logger(subsystem: "com.wudan.iris", category: "NetworkFilterManager")

  // MARK: - Filter Control

  /// Enable the network filter
  /// - Returns: The new filter state
  @discardableResult
  public static func enableFilter() async -> FilterState {
    logger.info("Enabling network filter...")

    do {
      let manager = NEFilterManager.shared()
      try await manager.loadFromPreferences()

      let filterConfig = NEFilterProviderConfiguration()
      filterConfig.filterPackets = false
      filterConfig.filterSockets = true

      manager.providerConfiguration = filterConfig
      manager.localizedDescription = "Iris Network Monitor"
      manager.isEnabled = true

      try await manager.saveToPreferences()

      logger.info("Network filter enabled")
      return .enabled

    } catch {
      logger.error("Failed to enable filter: \(error.localizedDescription)")
      return .disabled
    }
  }

  /// Disable the network filter
  /// - Returns: The new filter state
  @discardableResult
  public static func disableFilter() async -> FilterState {
    logger.info("Disabling network filter...")

    do {
      let manager = NEFilterManager.shared()
      try await manager.loadFromPreferences()

      manager.isEnabled = false
      try await manager.saveToPreferences()

      logger.info("Network filter disabled")
      return .disabled

    } catch {
      logger.error("Failed to disable filter: \(error.localizedDescription)")
      return .unknown
    }
  }

  /// Completely remove the network filter configuration
  public static func cleanConfiguration() async {
    logger.info("Cleaning network filter configuration...")

    do {
      let manager = NEFilterManager.shared()
      try await manager.loadFromPreferences()

      manager.providerConfiguration = nil
      manager.isEnabled = false

      try await manager.saveToPreferences()
      logger.info("Network filter configuration cleaned")
    } catch {
      logger.error("Failed to clean filter configuration: \(error.localizedDescription)")
    }
  }

  // MARK: - Status Checking

  /// Check if the network filter is installed and its current state
  /// - Returns: Tuple of (extension state, filter state)
  public static func checkStatus() async -> (ExtensionState, FilterState) {
    logger.info("Checking network filter status...")

    do {
      let manager = NEFilterManager.shared()
      try await manager.loadFromPreferences()

      if manager.providerConfiguration != nil {
        logger.info("Network extension is installed")
        let filterState: FilterState = manager.isEnabled ? .enabled : .disabled
        return (.installed, filterState)
      } else {
        logger.info("Network extension not installed")
        return (.notInstalled, .disabled)
      }
    } catch {
      logger.error("Failed to check network extension status: \(error.localizedDescription)")
      return (.notInstalled, .unknown)
    }
  }
}
