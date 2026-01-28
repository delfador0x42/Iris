//
//  main.swift
//  IrisNetworkExtension
//
//  Network Extension system extension for monitoring network connections
//

import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
