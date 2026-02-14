import Foundation
import os.log

/// Receives commands from CLI tools via DistributedNotificationCenter.
/// Enables Claude Code and scripts to remote-control the running Iris app.
///
/// Usage from CLI:
///   swift scripts/iris-ctl.swift status
///   swift scripts/iris-ctl.swift reinstall
///   swift scripts/iris-ctl.swift sendCA
@MainActor
final class CLICommandHandler {
  static let shared = CLICommandHandler()

  private let logger = Logger(subsystem: "com.wudan.iris", category: "CLICommand")
  static let commandName = Notification.Name("com.wudan.iris.command")
  static let responseName = Notification.Name("com.wudan.iris.response")
  static let statusPath = "/tmp/iris-status.json"

  func startListening() {
    DistributedNotificationCenter.default().addObserver(
      forName: Self.commandName,
      object: nil,
      queue: .main
    ) { [weak self] notification in
      Task { @MainActor in
        await self?.handleCommand(notification)
      }
    }
    logger.info("CLI command handler listening")
  }

  private func handleCommand(_ notification: Notification) async {
    guard let action = notification.userInfo?["action"] as? String else { return }
    logger.info("CLI command: \(action)")

    switch action {
    case "status":
      await writeStatus()

    case "reinstall":
      ExtensionManager.shared.cleanReinstallExtensions()
      respond("ok", action: "reinstall")

    case "startProxy":
      let ok = await TransparentProxyManager.enableProxy()
      respond(ok ? "ok" : "failed", action: "startProxy")

    case "stopProxy":
      await TransparentProxyManager.disableProxy()
      respond("ok", action: "stopProxy")

    case "sendCA":
      await IrisMainApp.sendCAToProxy()
      respond("ok", action: "sendCA")

    case "checkExtensions":
      await ExtensionManager.shared.checkAllExtensionStatuses()
      await writeStatus()

    case "cleanProxy":
      await TransparentProxyManager.cleanConfiguration()
      let cleaned = await TransparentProxyManager.enableProxy()
      respond(cleaned ? "ok" : "failed", action: "cleanProxy")

    case "installProxy":
      ExtensionManager.shared.installExtension(.proxy)
      respond("ok", action: "installProxy")

    case "installDNS":
      ExtensionManager.shared.installExtension(.dns)
      respond("ok", action: "installDNS")

    default:
      logger.warning("Unknown CLI command: \(action)")
      respond("error", action: action)
    }
  }

  private func writeStatus() async {
    await ExtensionManager.shared.checkAllExtensionStatuses()

    let em = ExtensionManager.shared
    let status: [String: Any] = [
      "timestamp": ISO8601DateFormatter().string(from: Date()),
      "extensions": [
        "network": em.networkExtensionState.description,
        "endpoint": em.endpointExtensionState.description,
        "proxy": em.proxyExtensionState.description,
        "dns": em.dnsExtensionState.description,
      ],
      "proxy": [
        "connected": ProxyStore.shared.isEnabled,
        "interception": ProxyStore.shared.isInterceptionEnabled,
        "flowCount": ProxyStore.shared.totalFlowCount,
      ],
      "ca": [
        "loaded": CertificateStore.shared.caCertificate != nil
      ],
    ]

    if let data = try? JSONSerialization.data(
      withJSONObject: status, options: [.prettyPrinted, .sortedKeys])
    {
      try? data.write(to: URL(fileURLWithPath: Self.statusPath))
    }

    respond("ok", action: "status")
  }

  private func respond(_ status: String, action: String) {
    DistributedNotificationCenter.default().postNotificationName(
      Self.responseName,
      object: nil,
      userInfo: ["status": status, "action": action],
      deliverImmediately: true
    )
  }
}
