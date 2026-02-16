import Foundation

// MARK: - Technique Registration + Binary/Process Techniques

extension FindingAnalyzer {

  typealias F = (String, AnomalySeverity, Int) -> Analysis

  /// Called once to populate the lookup tables.
  static func registerAll() {
    guard techniques.isEmpty else { return }
    var exact: [String: F] = [:]
    var prefix: [(String, F)] = []
    addBinaryTechniques(&exact)
    addProcessTechniques(&exact)
    addSystemTechniques(&exact, &prefix)
    techniques = exact
    prefixTechniques = prefix
  }

  // MARK: - Code Signing & Integrity

  private static func addBinaryTechniques(_ exact: inout [String: F]) {
    exact["Dylib Injection Detected"] = { proc, _, count in
      let cn = count > 1 ? " (\(count) loaded frameworks)" : ""
      return Analysis(
        whyItMatters: "Loaded libraries not in the binary's Mach-O headers may indicate injection.",
        whatsHappening: "\(proc) has loaded frameworks\(cn) not in its LC_LOAD_DYLIB commands.",
        severityContext: xcodeTool(proc)
          ? "Common for Xcode build tools. Likely benign on a dev machine."
          : "Unusual for \(proc). Could indicate runtime code injection.",
        recommendedAction: xcodeTool(proc)
          ? "Add to allowlist if this is your development machine."
          : "Verify with codesign -dvvv. Check parent process chain.")
    }
    exact["Unsigned Binary"] = { proc, _, _ in Analysis(
      whyItMatters: "Unsigned binaries bypass Gatekeeper and can't be verified.",
      whatsHappening: "\(proc) is running without a code signature.",
      severityContext: "Common for scripts, homebrew tools, dev builds. Suspicious in /System or /Applications.",
      recommendedAction: "Verify origin. Consider ad-hoc signing with codesign -s -.")
    }
    exact["Ad-hoc Signed"] = { proc, _, _ in Analysis(
      whyItMatters: "Ad-hoc signatures prove build identity but not publisher identity.",
      whatsHappening: "\(proc) has an ad-hoc code signature (no Apple Developer identity).",
      severityContext: "Normal for local dev builds and some open-source tools.",
      recommendedAction: "Verify the binary's origin if it's not something you built.")
    }
    exact["Ad-hoc Signed Application"] = exact["Ad-hoc Signed"]!
    exact["Dangerous Entitlement"] = { proc, _, count in Analysis(
      whyItMatters: "Entitlements like get-task-allow and task_for_pid grant deep system access.",
      whatsHappening: "\(proc) has \(count > 1 ? "\(count) dangerous entitlements" : "a dangerous entitlement").",
      severityContext: "Expected for Xcode, debuggers, dev-signed apps. Suspicious for production.",
      recommendedAction: "Verify entitlements match the app's purpose.")
    }
  }

  // MARK: - Process Integrity

  private static func addProcessTechniques(_ exact: inout [String: F]) {
    exact["Process Masquerade"] = { proc, _, _ in Analysis(
      whyItMatters: "A process whose name doesn't match its binary path may be impersonating a tool.",
      whatsHappening: "\(proc) has a name that doesn't correspond to its executable path.",
      severityContext: "Can happen with symlinks. Also a common malware evasion technique.",
      recommendedAction: "Check actual binary path. Verify code signature.")
    }
    exact["Hidden Process"] = { proc, _, _ in Analysis(
      whyItMatters: "Processes invisible to standard APIs may be using rootkit techniques.",
      whatsHappening: "\(proc) found via low-level enumeration but not standard process listing.",
      severityContext: "Rare and highly suspicious.",
      recommendedAction: "Investigate immediately. Check code signature and origin.")
    }
    exact["Duplicate System Process"] = { proc, _, _ in Analysis(
      whyItMatters: "System processes should have exactly one instance. Duplicates may be imposters.",
      whatsHappening: "Multiple instances of \(proc) found running simultaneously.",
      severityContext: "Highly suspicious. Malware often impersonates system process names.",
      recommendedAction: "Compare PIDs and binary paths. The imposter will have a different path.")
    }
    exact["Process Has Been Debugged/Injected"] = { proc, _, _ in Analysis(
      whyItMatters: "P_TRACED flag indicates a debugger or injector is attached.",
      whatsHappening: "\(proc) has the P_TRACED flag set.",
      severityContext: "Expected during development (Xcode, lldb). Suspicious for production.",
      recommendedAction: "If not debugging, investigate what attached to this process.")
    }
    exact["Missing Hardened Runtime Flags"] = { proc, _, _ in Analysis(
      whyItMatters: "Hardened runtime prevents code injection and DYLD hijacking.",
      whatsHappening: "\(proc) is missing hardened runtime protection.",
      severityContext: "Many third-party apps lack it. Apple apps should always have it.",
      recommendedAction: "Check for updates with hardened runtime.")
    }
    exact["Recently Modified System Binary"] = { proc, _, _ in Analysis(
      whyItMatters: "System binaries shouldn't change outside of OS updates.",
      whatsHappening: "\(proc) was recently modified on disk.",
      severityContext: "Can happen after OS updates or Xcode installations.",
      recommendedAction: "Verify against known-good hash.")
    }
  }

  /// Xcode build tools that commonly trigger dylib injection findings.
  static func xcodeTool(_ name: String) -> Bool {
    let tools = ["ibtool", "IBDesignablesAgent", "ibtoold", "actool",
                 "mapc", "momc", "xctest", "XCTRunner", "swiftc"]
    return tools.contains(name) || name.hasPrefix("IB") || name.hasPrefix("XC")
  }
}
