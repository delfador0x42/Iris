//
//  main.swift
//  IrisEndpointExtension
//
//  Endpoint Security system extension for process monitoring
//

import Foundation
import os.log

let logger = Logger(subsystem: "com.wudan.iris.endpoint", category: "Main")

logger.info("IrisEndpointExtension starting...")

// Create and start the ES client
let esClient = ESClient()

do {
    try esClient.start()
    logger.info("Endpoint Security client started successfully")
} catch {
    let msg = error.localizedDescription
    logger.error("Failed to start Endpoint Security client: \(msg)")
    esClient.startupError = msg
}

// Keep the extension running (XPC still serves even if ES failed)
dispatchMain()
