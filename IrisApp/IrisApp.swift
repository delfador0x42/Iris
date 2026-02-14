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
    .windowToolbarStyle(.unified(showsTitle: false))
    .defaultSize(width: 1200, height: 800)
  }

  init() {
    CLICommandHandler.shared.startListening()

    Task { @MainActor in
      // 1. Generate/load CA certificate
      await CertificateStore.shared.loadOrCreateCA()

      // 2. Ensure proxy tunnel is running (reconnects if needed, creates if missing)
      await TransparentProxyManager.ensureRunning()

      // 3. Send CA to proxy extension via XPC
      await IrisMainApp.sendCAToProxy()
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
