//
//  main.swift
//  IrisDNSExtension
//
//  Entry point for the DNS proxy system extension.
//

import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
