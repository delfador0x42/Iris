//
//  main.swift
//  IrisEndpointExtension
//
//  Endpoint Security system extension for process monitoring
//

import Foundation
import os.log

let logger = Logger(subsystem: "com.wudan.iris.endpoint", category: "Main")

logger.info("[MAIN] IrisEndpointExtension starting (PID \(getpid()), UID \(getuid()), EUID \(geteuid()))")

// Log basic environment info
let bundlePath = Bundle.main.bundlePath
logger.info("[MAIN] Bundle path: \(bundlePath)")
logger.info("[MAIN] Process name: \(ProcessInfo.processInfo.processName)")

// Create and start the ES client
let esClient = ESClient()

do {
    try esClient.start()
    logger.info("[MAIN] Endpoint Security client started successfully — ES events are flowing")
} catch {
    let msg = error.localizedDescription
    logger.error("[MAIN] FAILED to start Endpoint Security client: \(msg)")
    logger.error("[MAIN] ES will NOT monitor processes. XPC still serves for status queries.")
    esClient.startupError = msg
}

logger.info("[MAIN] Entering dispatchMain() — extension will run until terminated")

// Keep the extension running (XPC still serves even if ES failed)
dispatchMain()
