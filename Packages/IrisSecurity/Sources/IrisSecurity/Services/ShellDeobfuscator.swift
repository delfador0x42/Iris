import Foundation

/// Decodes common shell obfuscation techniques used to evade string matching.
/// Returns deobfuscated content + evidence of obfuscation patterns found.
///
/// Handles: ${IFS} substitution, $'\xNN' hex, $'\NNN' octal, printf hex,
/// quote splitting ('cu''rl'), and detects variable-based command hiding.
enum ShellDeobfuscator {

    struct Result {
        let decoded: String
        let evidence: [Evidence]
    }

    /// Main entry: deobfuscate content and collect evidence
    static func deobfuscate(_ content: String) -> Result {
        var ev: [Evidence] = []
        var text = content

        // Phase 1: Detect and decode specific patterns
        let (t1, e1) = decodeIFS(text)
        text = t1; ev.append(contentsOf: e1)

        let (t2, e2) = decodeHexEscapes(text)
        text = t2; ev.append(contentsOf: e2)

        let (t3, e3) = decodeOctalEscapes(text)
        text = t3; ev.append(contentsOf: e3)

        let (t4, e4) = decodePrintfHex(text)
        text = t4; ev.append(contentsOf: e4)

        let (t5, e5) = decodeQuoteSplitting(text)
        text = t5; ev.append(contentsOf: e5)

        // Phase 2: Detect patterns we can't fully decode but are suspicious
        ev.append(contentsOf: detectVariableSubstitution(content))
        ev.append(contentsOf: detectBacktickExec(content))

        return Result(decoded: text, evidence: ev)
    }

    // MARK: - ${IFS} substitution

    /// ${IFS} is Internal Field Separator — defaults to space/tab/newline.
    /// Attackers use it to hide spaces: cu${IFS}rl → curl (with space effect)
    private static func decodeIFS(_ text: String) -> (String, [Evidence]) {
        let pattern = "${IFS}"
        guard text.contains(pattern) else { return (text, []) }
        let count = text.components(separatedBy: pattern).count - 1
        let decoded = text.replacingOccurrences(of: pattern, with: " ")
        let ev = Evidence(
            factor: "${IFS} substitution (\(count)x) — space evasion",
            weight: 0.5, category: .content
        )
        return (decoded, [ev])
    }

    // MARK: - $'\xNN' hex escapes

    /// Bash/zsh $'...' quoting with \xNN hex escapes: $'\x63\x75\x72\x6c' → curl
    private static func decodeHexEscapes(_ text: String) -> (String, [Evidence]) {
        // Match $'...' blocks containing \x sequences
        guard let regex = try? NSRegularExpression(
            pattern: #"\$'((?:[^'\\]|\\x[0-9a-fA-F]{2}|\\.)*)'"#
        ) else { return (text, []) }

        var decoded = text
        let range = NSRange(text.startIndex..., in: text)
        let matches = regex.matches(in: text, range: range)
        guard !matches.isEmpty else { return (text, []) }

        var hexCount = 0
        // Process in reverse to preserve ranges
        for match in matches.reversed() {
            guard let innerRange = Range(match.range(at: 1), in: decoded) else { continue }
            let inner = String(decoded[innerRange])
            guard inner.contains("\\x") else { continue }
            let expanded = expandHexEscapes(inner)
            hexCount += inner.components(separatedBy: "\\x").count - 1
            let fullRange = Range(match.range, in: decoded)!
            decoded.replaceSubrange(fullRange, with: expanded)
        }

        guard hexCount > 0 else { return (text, []) }
        let ev = Evidence(
            factor: "Hex-escaped strings $'\\xNN' (\(hexCount) bytes) — character evasion",
            weight: 0.6, category: .content
        )
        return (decoded, [ev])
    }

    private static func expandHexEscapes(_ s: String) -> String {
        var result = ""
        var i = s.startIndex
        while i < s.endIndex {
            if s[i] == "\\" && s.index(after: i) < s.endIndex {
                let next = s.index(after: i)
                if s[next] == "x" {
                    let hexStart = s.index(next, offsetBy: 1, limitedBy: s.endIndex) ?? s.endIndex
                    let hexEnd = s.index(hexStart, offsetBy: 2, limitedBy: s.endIndex) ?? s.endIndex
                    if hexEnd <= s.endIndex {
                        let hex = String(s[hexStart..<hexEnd])
                        if let byte = UInt8(hex, radix: 16) {
                            result.append(Character(UnicodeScalar(byte)))
                            i = hexEnd
                            continue
                        }
                    }
                }
            }
            result.append(s[i])
            i = s.index(after: i)
        }
        return result
    }

    // MARK: - $'\NNN' octal escapes

    /// Bash/zsh $'...' with \NNN octal: $'\143\165\162\154' → curl
    private static func decodeOctalEscapes(_ text: String) -> (String, [Evidence]) {
        guard let regex = try? NSRegularExpression(
            pattern: #"\$'((?:[^'\\]|\\[0-7]{1,3}|\\.)*)'"#
        ) else { return (text, []) }

        var decoded = text
        let range = NSRange(text.startIndex..., in: text)
        let matches = regex.matches(in: text, range: range)
        guard !matches.isEmpty else { return (text, []) }

        var octalCount = 0
        for match in matches.reversed() {
            guard let innerRange = Range(match.range(at: 1), in: decoded) else { continue }
            let inner = String(decoded[innerRange])
            // Must have octal escapes (digit after backslash, not \x or \n etc)
            guard inner.range(of: #"\\[0-7]{1,3}"#, options: .regularExpression) != nil else { continue }
            let expanded = expandOctalEscapes(inner)
            if expanded != inner {
                octalCount += 1
                let fullRange = Range(match.range, in: decoded)!
                decoded.replaceSubrange(fullRange, with: expanded)
            }
        }

        guard octalCount > 0 else { return (text, []) }
        let ev = Evidence(
            factor: "Octal-escaped strings $'\\NNN' — character evasion",
            weight: 0.6, category: .content
        )
        return (decoded, [ev])
    }

    private static func expandOctalEscapes(_ s: String) -> String {
        var result = ""
        var i = s.startIndex
        while i < s.endIndex {
            if s[i] == "\\" {
                let next = s.index(after: i)
                if next < s.endIndex && s[next] >= "0" && s[next] <= "7" {
                    // Collect up to 3 octal digits
                    var octal = ""
                    var j = next
                    while j < s.endIndex && octal.count < 3 && s[j] >= "0" && s[j] <= "7" {
                        octal.append(s[j])
                        j = s.index(after: j)
                    }
                    if let byte = UInt8(octal, radix: 8), byte < 128 {
                        result.append(Character(UnicodeScalar(byte)))
                        i = j
                        continue
                    }
                }
            }
            result.append(s[i])
            i = s.index(after: i)
        }
        return result
    }

    // MARK: - printf '\xNN' execution

    /// $(printf '\x63\x75\x72\x6c') → curl
    private static func decodePrintfHex(_ text: String) -> (String, [Evidence]) {
        guard let regex = try? NSRegularExpression(
            pattern: #"\$\(printf\s+'((?:\\x[0-9a-fA-F]{2})+)'\)"#
        ) else { return (text, []) }

        var decoded = text
        let range = NSRange(text.startIndex..., in: text)
        let matches = regex.matches(in: text, range: range)
        guard !matches.isEmpty else { return (text, []) }

        for match in matches.reversed() {
            guard let innerRange = Range(match.range(at: 1), in: decoded) else { continue }
            let inner = String(decoded[innerRange])
            let expanded = expandHexEscapes(inner)
            let fullRange = Range(match.range, in: decoded)!
            decoded.replaceSubrange(fullRange, with: expanded)
        }

        let ev = Evidence(
            factor: "printf hex execution $(printf '\\xNN') — command obfuscation",
            weight: 0.7, category: .content
        )
        return (decoded, [ev])
    }

    // MARK: - Quote splitting

    /// 'cu''rl' → curl, "cu""rl" → curl
    /// Attackers split strings to break naive substring matching
    private static func decodeQuoteSplitting(_ text: String) -> (String, [Evidence]) {
        let hasSingleSplit = text.contains("''") && !text.contains("'''")
        let hasDoubleSplit = text.contains("\"\"") && !text.contains("\"\"\"")
        guard hasSingleSplit || hasDoubleSplit else { return (text, []) }

        var decoded = text
        // 'foo''bar' — adjacent single quotes joining strings
        decoded = decoded.replacingOccurrences(of: "''", with: "")
        // "foo""bar" — adjacent double quotes
        decoded = decoded.replacingOccurrences(of: "\"\"", with: "")

        // Only flag if it actually changed something meaningful
        guard decoded != text else { return (text, []) }
        let ev = Evidence(
            factor: "Quote-split strings — keyword fragmentation",
            weight: 0.3, category: .content
        )
        return (decoded, [ev])
    }

    // MARK: - Detection-only patterns (can't safely decode)

    /// Variable-based command hiding: c=curl; $c http://evil.com
    private static func detectVariableSubstitution(_ text: String) -> [Evidence] {
        let lines = text.components(separatedBy: "\n")
        let dangerousCommands = ["curl", "wget", "nc", "bash", "sh", "python", "perl", "ruby"]
        var found = false

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("#") { continue }
            for cmd in dangerousCommands {
                // Pattern: VAR=<cmd> or VAR="<cmd>" (assignment hiding a command name)
                let lower = trimmed.lowercased()
                if lower.range(of: #"[a-z_]+=["']?\#(cmd)["']?\s*$"#, options: .regularExpression) != nil ||
                   lower.range(of: #"[a-z_]+=["']?\#(cmd)["']?;"#, options: .regularExpression) != nil {
                    found = true
                    break
                }
            }
            if found { break }
        }

        guard found else { return [] }
        return [Evidence(
            factor: "Variable hides command name — possible evasion",
            weight: 0.4, category: .content
        )]
    }

    /// Backtick execution for command construction: `echo curl` http://evil.com
    private static func detectBacktickExec(_ text: String) -> [Evidence] {
        let lines = text.components(separatedBy: "\n")
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("#") { continue }
            // Backtick containing echo/printf that constructs a command
            if let range = trimmed.range(of: #"`[^`]*(?:echo|printf)[^`]*`"#, options: .regularExpression) {
                let inside = String(trimmed[range]).lowercased()
                let dangerous = ["curl", "wget", "nc", "bash", "sh", "python"]
                if dangerous.contains(where: { inside.contains($0) }) {
                    return [Evidence(
                        factor: "Backtick constructs command name — obfuscation",
                        weight: 0.5, category: .content
                    )]
                }
            }
        }
        return []
    }
}
