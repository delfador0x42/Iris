import Foundation

/// Detects algorithmically-generated domains (DGA) used for C2 resilience.
/// Uses 4 statistical features: consonant ratio, digit mixing, Shannon entropy,
/// and English bigram frequency. Designed for low false-positive on CDN/cloud domains.
public enum DGADetector {

    /// Returns true if the domain's second-level domain looks algorithmically generated.
    public static func isDGA(_ domain: String) -> Bool {
        let sld = extractSLD(domain)
        guard sld.count >= 8 else { return false }

        let consonantRatio = consonantRatio(sld)
        let digitRatio = digitMixingRatio(sld)
        let entropy = shannonEntropy(sld)
        let bigramScore = englishBigramRatio(sld)

        // DGA score: high entropy + low English structure + high consonant density
        // Tuned to catch random strings while allowing common words
        let score = entropy * (1.0 - bigramScore) * consonantRatio
        return score > 1.8 || (digitRatio > 0.3 && entropy > 3.0)
    }

    // MARK: - Features

    private static let vowels: Set<Character> = ["a", "e", "i", "o", "u"]

    private static func consonantRatio(_ s: String) -> Double {
        let letters = s.filter(\.isLetter)
        guard !letters.isEmpty else { return 0 }
        let consonants = letters.filter { !vowels.contains($0) }
        return Double(consonants.count) / Double(letters.count)
    }

    private static func digitMixingRatio(_ s: String) -> Double {
        guard !s.isEmpty else { return 0 }
        let digits = s.filter(\.isNumber)
        return Double(digits.count) / Double(s.count)
    }

    private static func shannonEntropy(_ s: String) -> Double {
        var freq: [Character: Int] = [:]
        for c in s { freq[c, default: 0] += 1 }
        let len = Double(s.count)
        return -freq.values.reduce(0.0) { acc, count in
            let p = Double(count) / len
            return acc + p * log2(p)
        }
    }

    /// Ratio of character bigrams that appear in common English
    private static func englishBigramRatio(_ s: String) -> Double {
        let lower = s.lowercased()
        guard lower.count >= 2 else { return 0 }
        var total = 0
        var hits = 0
        let chars = Array(lower)
        for i in 0..<(chars.count - 1) {
            let bigram = String(chars[i]) + String(chars[i + 1])
            if bigram.allSatisfy(\.isLetter) {
                total += 1
                if commonBigrams.contains(bigram) { hits += 1 }
            }
        }
        return total > 0 ? Double(hits) / Double(total) : 0
    }

    /// Extract second-level domain: "foo.example.com" → "example"
    private static func extractSLD(_ domain: String) -> String {
        let parts = domain.split(separator: ".")
        guard parts.count >= 2 else { return domain }
        return String(parts[parts.count - 2]).lowercased()
    }

    /// Top English bigrams (covers ~60% of English text bigram frequency)
    private static let commonBigrams: Set<String> = [
        "th", "he", "in", "en", "nt", "re", "er", "an", "ti", "on",
        "at", "se", "nd", "or", "ar", "al", "te", "co", "de", "to",
        "ra", "et", "ed", "it", "sa", "em", "ro", "st", "es", "le",
        "ou", "el", "ha", "li", "ri", "ne", "ea", "ve", "me", "io",
        "ce", "is", "si", "la", "ta", "no", "ma", "ng", "ic", "ch",
    ]
}
