import Security
import SwiftUI
import os.log

@main
struct IrisMainApp: App {
  @StateObject private var extensionManager = ExtensionManager.shared

  var body: some Scene {
    WindowGroup {
      if extensionManager.areAllExtensionsReady {
        HomeView()
      } else {
        ExtensionSetupView()
      }
    }
    .windowStyle(.hiddenTitleBar)
    .defaultSize(width: 1200, height: 800)
  }

  init() {
    CLICommandHandler.shared.startListening()
    ProbeRunner.shared.registerDefaultProbes()

    Task { @MainActor in
      // 1. Generate/load CA certificate
      await CertificateStore.shared.loadOrCreateCA()

      // 2. Ensure proxy tunnel is running (reconnects if needed, creates if missing)
      await TransparentProxyManager.ensureRunning()

      // 3. Send CA to proxy extension via XPC
      await IrisMainApp.sendCAToProxy()

      // 4. Initialize detection engine with all rules, start event bus
      await RuleLoader.loadAll()
      await SecurityEventBus.shared.start()

      // 5. Push threat intel blocklists to endpoint extension
      await IrisMainApp.pushThreatIntel()

      // 6. Bridge network + DNS data into the detection pipeline
      await NetworkEventBridge.shared.start()
      await DNSEventBridge.shared.start()
    }
  }

  @MainActor
  static func pushThreatIntel() async {
    let logger = Logger(subsystem: "com.wudan.iris", category: "IrisApp")
    let indicators = ThreatIntelStore.allIndicators()
    let paths = indicators.filter { $0.type == .filePath }.map(\.value)
    let signingIds = indicators.filter { $0.type == .signingId }.map(\.value)
    guard !paths.isEmpty || !signingIds.isEmpty else { return }

    let conn = NSXPCConnection(machServiceName: EndpointXPCService.extensionServiceName)
    conn.remoteObjectInterface = NSXPCInterface(with: EndpointXPCProtocol.self)
    conn.resume()
    defer { conn.invalidate() }

    guard let proxy = conn.remoteObjectProxyWithErrorHandler({ error in
      logger.error("[THREAT-INTEL] XPC error: \(error.localizedDescription)")
    }) as? EndpointXPCProtocol else { return }

    let ok: Bool = await withCheckedContinuation { cont in
      proxy.updateBlocklists(paths: paths, teamIds: [], signingIds: signingIds) { ok in
        cont.resume(returning: ok)
      }
    }
    if ok {
      logger.info("[THREAT-INTEL] Pushed \(paths.count) paths, \(signingIds.count) sigIDs to ExecPolicy")
    }
  }

  @MainActor
  static func sendCAToProxy() async {
    let logger = Logger(subsystem: "com.wudan.iris", category: "IrisApp")

    guard let cert = CertificateStore.shared.caCertificate,
      let key = CertificateStore.shared.caPrivateKey
    else {
      logger.error("CA not available — cannot send to proxy extension")
      return
    }

    let certData = SecCertificateCopyData(cert) as Data

    var error: Unmanaged<CFError>?
    guard let keyData = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
      logger.error("Failed to export CA key")
      return
    }

    // Retry — proxy extension may not have started its XPC listener yet
    for attempt in 1...10 {
      ProxyStore.shared.connect()
      try? await Task.sleep(nanoseconds: 1_000_000_000)
      let success = await ProxyStore.shared.sendCA(certData: certData, keyData: keyData)
      if success {
        logger.info("CA sent to proxy extension (attempt \(attempt))")
        return
      }
      logger.warning("CA send attempt \(attempt) failed, retrying...")
      ProxyStore.shared.disconnect()
    }
    logger.error("Failed to send CA to proxy extension after 10 attempts")
  }
}
