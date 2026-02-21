//
//  RulePersistence.swift
//  IrisProxyExtension
//
//  Persists SecurityRule array to extension container as JSON.
//  Absorbed from IrisNetworkExtension.
//

import Foundation
import os.log

enum RulePersistence {
    private static let logger = Logger(
        subsystem: "com.wudan.iris.proxy",
        category: "RulePersistence"
    )

    private static var rulesFileURL: URL? {
        guard let support = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else { return nil }

        let dir = support.appendingPathComponent("com.wudan.iris.proxy.extension")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("rules.json")
    }

    static func save(_ rules: [SecurityRule]) {
        guard let url = rulesFileURL else {
            logger.error("No writable path for rule persistence")
            return
        }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(rules) else { return }
        try? data.write(to: url, options: .atomic)
        logger.debug("Saved \(rules.count) rules")
    }

    static func load() -> [SecurityRule] {
        guard let url = rulesFileURL,
              let data = try? Data(contentsOf: url) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let rules = (try? decoder.decode([SecurityRule].self, from: data)) ?? []
        logger.info("Loaded \(rules.count) persisted rules")
        return rules
    }
}
