//
//  main.swift
//  IrisProxyExtension
//
//  System extension for transparent HTTPS proxy with TLS interception.
//  Uses NEAppProxyProvider to intercept and inspect HTTP/HTTPS traffic.
//

import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
