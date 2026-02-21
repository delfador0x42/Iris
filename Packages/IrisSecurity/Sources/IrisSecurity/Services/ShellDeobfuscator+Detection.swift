import Foundation

/// Detection-only patterns: identify suspicious shell constructs that can't be safely decoded.
extension ShellDeobfuscator {

    // MARK: - Variable substitution detection

    /// Variable-based command hiding: c=curl; $c http://evil.com
    /// Uses string ops instead of regex — 16 regex/line was the #1 CPU bottleneck.
    static func detectVariableSubstitution(_ text: String) -> [Evidence] {
        let dangerousCommands = ["curl", "wget", "nc", "bash", "sh", "python", "perl", "ruby"]
        for line in text.split(separator: "\n") {
            let trimmed = line.drop(while: { $0 == " " || $0 == "\t" })
            if trimmed.hasPrefix("#") { continue }
            guard let eqIdx = trimmed.firstIndex(of: "=") else { continue }
            // Must have a letter/underscore before '=' (variable name)
            guard eqIdx > trimmed.startIndex else { continue }
            let beforeEq = trimmed[trimmed.startIndex..<eqIdx]
            guard beforeEq.allSatisfy({ $0.isLetter || $0 == "_" || $0.isNumber }) else { continue }
            // Extract value after '=', strip quotes
            var value = trimmed[trimmed.index(after: eqIdx)...]
            // Strip trailing ; if present
            if value.hasSuffix(";") { value = value.dropLast() }
            // Strip surrounding quotes
            let stripped = value.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            let lower = stripped.lowercased()
            if dangerousCommands.contains(lower) {
                return [Evidence(
                    factor: "Variable hides command name — possible evasion",
                    weight: 0.4, category: .content
                )]
            }
        }
        return []
    }

    // MARK: - Backtick execution detection

    /// Backtick execution for command construction: `echo curl` http://evil.com
    static func detectBacktickExec(_ text: String) -> [Evidence] {
        // Fast bail: no backticks at all
        guard text.contains("`") else { return [] }
        let dangerous = ["curl", "wget", "nc", "bash", "sh", "python"]
        for line in text.split(separator: "\n") {
            let trimmed = line.drop(while: { $0 == " " || $0 == "\t" })
            if trimmed.hasPrefix("#") { continue }
            // Find backtick pairs containing echo/printf
            guard let first = trimmed.firstIndex(of: "`") else { continue }
            let afterFirst = trimmed.index(after: first)
            guard afterFirst < trimmed.endIndex,
                  let second = trimmed[afterFirst...].firstIndex(of: "`") else { continue }
            let inside = String(trimmed[first...second]).lowercased()
            guard inside.contains("echo") || inside.contains("printf") else { continue }
            if dangerous.contains(where: { inside.contains($0) }) {
                return [Evidence(
                    factor: "Backtick constructs command name — obfuscation",
                    weight: 0.5, category: .content
                )]
            }
        }
        return []
    }
}
