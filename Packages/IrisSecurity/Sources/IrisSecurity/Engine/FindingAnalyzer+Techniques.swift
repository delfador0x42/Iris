import Foundation

// MARK: - Technique Dictionary

extension FindingAnalyzer {

  typealias F = (String, AnomalySeverity, Int) -> Analysis

  /// Called once to populate the lookup tables.
  static func registerAll() {
    guard techniques.isEmpty else { return }

    let t = buildTechniques()
    techniques = t.exact
    prefixTechniques = t.prefix
  }

  private static func buildTechniques() -> (exact: [String: F], prefix: [(String, F)]) {
    var exact: [String: F] = [:]
    var prefix: [(String, F)] = []

    // -- Code Signing & Integrity --

    exact["Dylib Injection Detected"] = { proc, _, count in
      let cn = count > 1 ? " (\(count) loaded frameworks)" : ""
      return Analysis(
        whyItMatters: "Loaded libraries not declared in the binary's Mach-O headers may indicate injection via DYLD_INSERT_LIBRARIES or task_for_pid.",
        whatsHappening: "\(proc) has loaded frameworks\(cn) that aren't in its LC_LOAD_DYLIB commands. This happens when code is injected at runtime.",
        severityContext: xcodeTool(proc)
          ? "Common for Xcode build tools (ibtool, IBDesignablesAgent) which load plugin frameworks dynamically. Likely benign on a dev machine."
          : "Unusual for \(proc). Could indicate runtime code injection.",
        recommendedAction: xcodeTool(proc)
          ? "Add to allowlist if this is your development machine."
          : "Verify the process with codesign -dvvv. Check parent process chain.")
    }

    exact["Unsigned Binary"] = { proc, _, _ in Analysis(
      whyItMatters: "Unsigned binaries bypass Gatekeeper and can't be verified for integrity.",
      whatsHappening: "\(proc) is running without a code signature.",
      severityContext: "Common for scripts, homebrew tools, and dev builds. Suspicious for anything in /System or /Applications.",
      recommendedAction: "Verify origin. Consider ad-hoc signing with codesign -s -.")
    }

    exact["Ad-hoc Signed"] = { proc, _, _ in Analysis(
      whyItMatters: "Ad-hoc signatures prove build identity but not publisher identity. No revocation possible.",
      whatsHappening: "\(proc) has an ad-hoc code signature (no Apple Developer identity).",
      severityContext: "Normal for local dev builds and some open-source tools.",
      recommendedAction: "Verify the binary's origin if it's not something you built.")
    }

    exact["Ad-hoc Signed Application"] = exact["Ad-hoc Signed"]!

    exact["Dangerous Entitlement"] = { proc, _, count in Analysis(
      whyItMatters: "Entitlements like get-task-allow, task_for_pid, and disable-library-validation grant deep system access.",
      whatsHappening: "\(proc) has \(count > 1 ? "\(count) dangerous entitlements" : "a dangerous entitlement") that could allow debugging, injection, or unsigned code loading.",
      severityContext: "Expected for Xcode, debuggers, and dev-signed apps. Suspicious for production apps.",
      recommendedAction: "Verify the entitlement matches the app's purpose. Production apps should not have get-task-allow.")
    }

    // -- Process Integrity --

    exact["Process Masquerade"] = { proc, _, _ in Analysis(
      whyItMatters: "A process whose name doesn't match its binary path may be impersonating a legitimate tool.",
      whatsHappening: "\(proc) has a name that doesn't correspond to its executable path on disk.",
      severityContext: "Can happen with symlinks or renamed binaries. Also a common malware evasion technique.",
      recommendedAction: "Check the actual binary path with `ls -la`. Verify code signature.")
    }

    exact["Hidden Process"] = { proc, _, _ in Analysis(
      whyItMatters: "Processes not visible through standard APIs may be using rootkit techniques to hide.",
      whatsHappening: "\(proc) was found through low-level enumeration but not through standard process listing.",
      severityContext: "Rare and highly suspicious. Some legitimate tools use process hiding but it's uncommon.",
      recommendedAction: "Investigate immediately. Check the binary's code signature and origin.")
    }

    exact["Duplicate System Process"] = { proc, _, _ in Analysis(
      whyItMatters: "System processes (loginwindow, WindowServer, etc.) should have exactly one instance. Duplicates may be imposters.",
      whatsHappening: "Multiple instances of \(proc) were found running simultaneously.",
      severityContext: "Highly suspicious. Malware often impersonates system process names.",
      recommendedAction: "Compare PIDs and binary paths of each instance. The imposter will have a different path.")
    }

    exact["Process Has Been Debugged/Injected"] = { proc, _, _ in Analysis(
      whyItMatters: "The P_TRACED flag indicates a debugger or injector is attached to this process.",
      whatsHappening: "\(proc) has the P_TRACED flag set, indicating active debugging or code injection.",
      severityContext: "Expected during development (Xcode, lldb). Suspicious for production processes.",
      recommendedAction: "If not actively debugging, investigate what attached to this process.")
    }

    exact["Missing Hardened Runtime Flags"] = { proc, _, _ in Analysis(
      whyItMatters: "Hardened runtime prevents code injection, DYLD hijacking, and debugger attachment.",
      whatsHappening: "\(proc) is missing hardened runtime protection, making it vulnerable to injection.",
      severityContext: "Many third-party apps lack hardened runtime. First-party Apple apps should always have it.",
      recommendedAction: "Check if this is a third-party app and whether updates are available with hardened runtime.")
    }

    exact["Recently Modified System Binary"] = { proc, _, _ in Analysis(
      whyItMatters: "System binaries should not change outside of OS updates. Modification may indicate tampering.",
      whatsHappening: "\(proc) was recently modified on disk.",
      severityContext: "Can happen after OS updates or Xcode installations. Suspicious otherwise.",
      recommendedAction: "Verify against known-good hash. Check file modification time vs last OS update.")
    }

    // -- System Integrity --

    exact["SIP Disabled"] = { _, _, _ in Analysis(
      whyItMatters: "System Integrity Protection prevents modification of system files, kernel extensions, and protected processes.",
      whatsHappening: "SIP is fully disabled on this machine, removing core OS protections.",
      severityContext: "You've deliberately disabled SIP (required for Iris endpoint security). This is expected on this machine.",
      recommendedAction: "Re-enable SIP when not actively developing security tools: csrutil enable from Recovery Mode.")
    }

    exact["AMFI Disabled"] = { _, _, _ in Analysis(
      whyItMatters: "Apple Mobile File Integrity enforces code signing. Disabling it allows unsigned code execution.",
      whatsHappening: "AMFI is disabled, meaning any unsigned code can execute without restriction.",
      severityContext: "Often disabled alongside SIP for development. Significantly weakens security.",
      recommendedAction: "Re-enable unless required for your current workflow.")
    }

    exact["Insecure Kernel"] = { _, _, _ in Analysis(
      whyItMatters: "kern.secure_kernel=0 means the kernel task port may be accessible to userspace.",
      whatsHappening: "The kernel is running in non-secure mode, potentially exposing kernel memory to processes.",
      severityContext: "Typically set when SIP is disabled. Expected on this machine.",
      recommendedAction: "Re-enable SIP to restore secure kernel mode.")
    }

    exact["Firewall Disabled"] = { _, _, _ in Analysis(
      whyItMatters: "The application firewall blocks incoming connections to unauthorized services.",
      whatsHappening: "The macOS application firewall is disabled, allowing any process to accept network connections.",
      severityContext: "Many developers disable the firewall for local server testing. Moderate risk.",
      recommendedAction: "Enable in System Settings > Network > Firewall unless you need incoming connections.")
    }

    // -- Persistence --

    exact["Hidden LaunchAgent/Daemon"] = { proc, _, _ in Analysis(
      whyItMatters: "LaunchAgents/Daemons that are hidden (prefixed with .) or in unusual locations may be malware persistence.",
      whatsHappening: "\(proc) is a hidden launch item that runs automatically.",
      severityContext: "Some legitimate tools use hidden plists. Check the binary it points to.",
      recommendedAction: "Read the plist to see what binary it launches. Verify that binary's signature.")
    }

    exact["SSH Authorized Keys"] = { _, _, _ in Analysis(
      whyItMatters: "SSH authorized_keys allow passwordless remote access. Unauthorized entries = backdoor.",
      whatsHappening: "SSH authorized keys file exists with entries that could allow remote login.",
      severityContext: "Normal if you use SSH. Verify each key belongs to you or a trusted party.",
      recommendedAction: "Review ~/.ssh/authorized_keys. Remove any keys you don't recognize.")
    }

    exact["Sudoers NOPASSWD"] = { proc, _, _ in Analysis(
      whyItMatters: "NOPASSWD entries allow privilege escalation without authentication.",
      whatsHappening: "\(proc) can run sudo commands without a password prompt.",
      severityContext: "Sometimes configured for automation scripts. High risk if unexpected.",
      recommendedAction: "Review /etc/sudoers and /etc/sudoers.d/. Remove any NOPASSWD rules you didn't create.")
    }

    // -- Network --

    exact["Web Proxy Configured"] = { _, _, _ in Analysis(
      whyItMatters: "A web proxy can intercept and modify all HTTP/HTTPS traffic.",
      whatsHappening: "A web proxy is configured in system network settings.",
      severityContext: "Normal in corporate environments. Suspicious if you didn't set it up.",
      recommendedAction: "Verify the proxy address in System Settings > Network > Proxies.")
    }

    exact["Hosts File Tampering"] = { _, _, _ in Analysis(
      whyItMatters: "The /etc/hosts file overrides DNS resolution. Malware uses this to redirect traffic.",
      whatsHappening: "Custom entries found in /etc/hosts that redirect domain names.",
      severityContext: "Developers often add localhost entries. Suspicious if pointing to unknown IPs.",
      recommendedAction: "Review /etc/hosts. Remove entries you didn't add.")
    }

    exact["Cloud C2/Exfiltration"] = { proc, _, _ in Analysis(
      whyItMatters: "Cloud-based command & control uses legitimate services (Dropbox, Slack, etc.) to evade network detection.",
      whatsHappening: "\(proc) has network connections to cloud services that could be used for C2 or data exfiltration.",
      severityContext: "Many legitimate apps connect to cloud services. Context matters — is this expected?",
      recommendedAction: "Verify \(proc) should be connecting to these services. Check data volumes.")
    }

    // -- Credential Access --

    exact["Open Handle to Credential File"] = { proc, _, _ in Analysis(
      whyItMatters: "Active file handles to credential stores (keychain, browser profiles) may indicate theft in progress.",
      whatsHappening: "\(proc) has an open file handle to a credential storage file.",
      severityContext: "Normal for browsers, keychain access. Suspicious for scripts or unknown binaries.",
      recommendedAction: "Verify \(proc) has a legitimate reason to access credentials.")
    }

    exact["Plaintext Credential File"] = { _, _, _ in Analysis(
      whyItMatters: "Credentials stored in plaintext can be trivially stolen by any process with file access.",
      whatsHappening: "A file containing plaintext credentials was found on disk.",
      severityContext: "Common in dev environments (.env files, config files). Should not exist on production.",
      recommendedAction: "Move credentials to Keychain or a secrets manager. Delete plaintext copies.")
    }

    // -- LOLBins & Evasion --

    exact["Exploit Tool Running"] = { proc, _, _ in Analysis(
      whyItMatters: "Security exploitation tools (Metasploit, Cobalt Strike, etc.) indicate active pentesting or compromise.",
      whatsHappening: "\(proc) is a known security exploitation framework.",
      severityContext: "Expected if you're doing authorized security testing. Critical if unexpected.",
      recommendedAction: "If not your pentest, treat as active compromise. Investigate immediately.")
    }

    exact["Exploit Tool Installed"] = { proc, _, _ in Analysis(
      whyItMatters: "Installed exploit tools could be used for later attacks even if not currently running.",
      whatsHappening: "\(proc) (a known exploit tool) is installed on disk.",
      severityContext: "Expected for security researchers. Remove if no longer needed.",
      recommendedAction: "Verify you installed this. Remove if unused to reduce attack surface.")
    }

    exact["Gatekeeper Bypass"] = { proc, _, _ in Analysis(
      whyItMatters: "Gatekeeper prevents execution of unverified software. Bypassing it removes a key defense layer.",
      whatsHappening: "\(proc) appears to have bypassed Gatekeeper checks.",
      severityContext: "Some developer workflows bypass Gatekeeper. Malware also uses this technique.",
      recommendedAction: "Verify the binary's origin and code signature.")
    }

    // -- Misc --

    exact["Suspicious TCC Grant"] = { proc, _, _ in Analysis(
      whyItMatters: "TCC (Transparency, Consent, Control) grants control access to camera, mic, screen, disk, etc.",
      whatsHappening: "\(proc) has been granted a TCC permission that may be excessive for its purpose.",
      severityContext: "Review whether this app needs this permission. Some grants persist after uninstall.",
      recommendedAction: "Check System Settings > Privacy & Security. Revoke if the app doesn't need it.")
    }

    exact["Surveillance TCC Grant"] = { proc, _, _ in Analysis(
      whyItMatters: "Screen recording and accessibility permissions allow a process to monitor all user activity.",
      whatsHappening: "\(proc) has permissions that could enable surveillance (screen capture, accessibility).",
      severityContext: "Expected for screen sharing tools, IDEs, and accessibility apps.",
      recommendedAction: "Verify \(proc) needs these permissions. Revoke in System Settings if not.")
    }

    exact["Ransomware Behavior"] = { proc, _, _ in Analysis(
      whyItMatters: "Ransomware encrypts files and demands payment. Early detection is critical.",
      whatsHappening: "\(proc) shows behavior consistent with ransomware: rapid file modification with high entropy.",
      severityContext: "Critical if unexpected. Could be legitimate encryption (FileVault, disk images).",
      recommendedAction: "STOP the process immediately if not recognized. Disconnect from network. Check backups.")
    }

    // -- Prefix matches for dynamic technique names --

    prefix.append(("Kext Hooks", { proc, _, _ in Analysis(
      whyItMatters: "Kernel extensions that hook system calls can intercept or modify any OS operation.",
      whatsHappening: "\(proc.isEmpty ? "A kext" : proc) is hooking kernel functions, giving it control over system behavior.",
      severityContext: "Some security tools and virtualization software use kext hooks. Malware rootkits also use this.",
      recommendedAction: "Verify the kext's publisher. Apple-signed kexts from known vendors are generally safe.") }))

    prefix.append(("Credential Access:", { proc, _, _ in Analysis(
      whyItMatters: "Credential access attempts may indicate password theft or credential dumping.",
      whatsHappening: "\(proc) is accessing credential-related resources.",
      severityContext: "Browsers and password managers legitimately access credentials. Scripts doing so are suspicious.",
      recommendedAction: "Verify \(proc) has a legitimate reason. Check process lineage.") }))

    prefix.append(("DYLD_INSERT_LIBRARIES", { proc, _, _ in Analysis(
      whyItMatters: "DYLD_INSERT_LIBRARIES forces a dylib into every process, enabling system-wide code injection.",
      whatsHappening: "\(proc) has DYLD_INSERT_LIBRARIES set, injecting code at process launch.",
      severityContext: "Used by some debugging tools (dtrace, Instruments). Malware uses it for persistence.",
      recommendedAction: "Check what dylib is being injected. Remove the environment variable if unexpected.") }))

    prefix.append(("Shell Profile", { proc, _, _ in Analysis(
      whyItMatters: "Shell profile modifications execute code every time a terminal opens — reliable persistence.",
      whatsHappening: "\(proc.isEmpty ? "A shell profile" : proc) contains suspicious environment variable or command injection.",
      severityContext: "Developers often customize shell profiles. Check for DYLD_ variables and unknown scripts.",
      recommendedAction: "Review ~/.zshrc, ~/.bash_profile, and /etc/profile.d/. Remove unfamiliar entries.") }))

    prefix.append(("Plist", { proc, _, _ in Analysis(
      whyItMatters: "Plist-based environment injection persists across reboots via launchd configuration.",
      whatsHappening: "\(proc.isEmpty ? "A LaunchAgent/Daemon plist" : proc) sets DYLD_ environment variables.",
      severityContext: "Rarely legitimate. Most apps don't need DYLD environment injection.",
      recommendedAction: "Remove the DYLD entries from the plist. Investigate who created it.") }))

    prefix.append(("Suspicious", { proc, _, _ in Analysis(
      whyItMatters: "This item was flagged as unusual compared to expected system configuration.",
      whatsHappening: "\(proc.isEmpty ? "An item" : proc) exhibits behavior that deviates from normal patterns.",
      severityContext: "Depends on context. May be a legitimate configuration change or an indicator of compromise.",
      recommendedAction: "Review the specific details and verify the item's origin.") }))

    return (exact: exact, prefix: prefix)
  }

  /// Xcode build tools that commonly trigger dylib injection findings.
  private static func xcodeTool(_ name: String) -> Bool {
    let tools = ["ibtool", "IBDesignablesAgent", "ibtoold", "actool",
                 "mapc", "momc", "xctest", "XCTRunner", "swiftc"]
    return tools.contains(name) || name.hasPrefix("IB") || name.hasPrefix("XC")
  }
}
