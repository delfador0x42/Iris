import Foundation

// MARK: - System, Persistence, Network, Credential, Evasion Techniques

extension FindingAnalyzer {

  /// Register system/threat/network techniques + all prefix matchers.
  static func addSystemTechniques(_ exact: inout [String: F], _ prefix: inout [(String, F)]) {
    addSystemIntegrity(&exact)
    addPersistenceTechniques(&exact)
    addNetworkTechniques(&exact)
    addCredentialTechniques(&exact)
    addEvasionTechniques(&exact)
    addMiscTechniques(&exact)
    addPrefixMatchers(&prefix)
  }

  // MARK: - System Integrity

  private static func addSystemIntegrity(_ exact: inout [String: F]) {
    exact["SIP Disabled"] = { _, _, _ in Analysis(
      whyItMatters: "SIP prevents modification of system files and protected processes.",
      whatsHappening: "SIP is fully disabled on this machine.",
      severityContext: "You've deliberately disabled SIP (required for Iris). Expected here.",
      recommendedAction: "Re-enable when not developing security tools: csrutil enable from Recovery.")
    }
    exact["AMFI Disabled"] = { _, _, _ in Analysis(
      whyItMatters: "AMFI enforces code signing. Disabling allows unsigned code execution.",
      whatsHappening: "AMFI is disabled — any unsigned code can execute.",
      severityContext: "Often disabled alongside SIP for development.",
      recommendedAction: "Re-enable unless required for your workflow.")
    }
    exact["Insecure Kernel"] = { _, _, _ in Analysis(
      whyItMatters: "kern.secure_kernel=0 means kernel task port may be accessible.",
      whatsHappening: "Kernel running in non-secure mode.",
      severityContext: "Typically set when SIP is disabled. Expected here.",
      recommendedAction: "Re-enable SIP to restore secure kernel mode.")
    }
    exact["Firewall Disabled"] = { _, _, _ in Analysis(
      whyItMatters: "The application firewall blocks unauthorized incoming connections.",
      whatsHappening: "macOS application firewall is disabled.",
      severityContext: "Many developers disable for local server testing. Moderate risk.",
      recommendedAction: "Enable in System Settings > Network > Firewall.")
    }
  }

  // MARK: - Persistence

  private static func addPersistenceTechniques(_ exact: inout [String: F]) {
    exact["Hidden LaunchAgent/Daemon"] = { proc, _, _ in Analysis(
      whyItMatters: "Hidden launch items (prefixed with .) may be malware persistence.",
      whatsHappening: "\(proc) is a hidden launch item that runs automatically.",
      severityContext: "Some tools use hidden plists. Check the binary it points to.",
      recommendedAction: "Read the plist. Verify the binary's signature.")
    }
    exact["SSH Authorized Keys"] = { _, _, _ in Analysis(
      whyItMatters: "SSH authorized_keys allow passwordless remote access.",
      whatsHappening: "SSH authorized keys file with entries that allow remote login.",
      severityContext: "Normal if you use SSH. Verify each key is yours.",
      recommendedAction: "Review ~/.ssh/authorized_keys. Remove unrecognized keys.")
    }
    exact["Sudoers NOPASSWD"] = { proc, _, _ in Analysis(
      whyItMatters: "NOPASSWD allows privilege escalation without authentication.",
      whatsHappening: "\(proc) can run sudo without a password prompt.",
      severityContext: "Sometimes configured for automation. High risk if unexpected.",
      recommendedAction: "Review /etc/sudoers. Remove NOPASSWD rules you didn't create.")
    }
  }

  // MARK: - Network

  private static func addNetworkTechniques(_ exact: inout [String: F]) {
    exact["Web Proxy Configured"] = { _, _, _ in Analysis(
      whyItMatters: "A web proxy can intercept and modify all HTTP/HTTPS traffic.",
      whatsHappening: "Web proxy configured in system network settings.",
      severityContext: "Normal in corporate environments. Suspicious if unexpected.",
      recommendedAction: "Verify proxy in System Settings > Network > Proxies.")
    }
    exact["Hosts File Tampering"] = { _, _, _ in Analysis(
      whyItMatters: "/etc/hosts overrides DNS. Malware uses this to redirect traffic.",
      whatsHappening: "Custom entries in /etc/hosts redirecting domain names.",
      severityContext: "Developers add localhost entries. Suspicious if pointing to unknown IPs.",
      recommendedAction: "Review /etc/hosts. Remove entries you didn't add.")
    }
    exact["Cloud C2/Exfiltration"] = { proc, _, _ in Analysis(
      whyItMatters: "Cloud C2 uses legitimate services to evade network detection.",
      whatsHappening: "\(proc) connecting to cloud services potentially used for C2.",
      severityContext: "Many apps connect to cloud services. Is this expected?",
      recommendedAction: "Verify \(proc) should connect to these services. Check data volumes.")
    }
  }

  // MARK: - Credential Access

  private static func addCredentialTechniques(_ exact: inout [String: F]) {
    exact["Open Handle to Credential File"] = { proc, _, _ in Analysis(
      whyItMatters: "Open handles to credential stores may indicate theft in progress.",
      whatsHappening: "\(proc) has an open handle to a credential storage file.",
      severityContext: "Normal for browsers, keychain. Suspicious for scripts.",
      recommendedAction: "Verify \(proc) has legitimate reason to access credentials.")
    }
    exact["Plaintext Credential File"] = { _, _, _ in Analysis(
      whyItMatters: "Plaintext credentials can be stolen by any process with file access.",
      whatsHappening: "File containing plaintext credentials found on disk.",
      severityContext: "Common in dev environments (.env files). Shouldn't exist in production.",
      recommendedAction: "Move to Keychain or secrets manager. Delete plaintext copies.")
    }
  }

  // MARK: - Evasion & Exploit Tools

  private static func addEvasionTechniques(_ exact: inout [String: F]) {
    exact["Exploit Tool Running"] = { proc, _, _ in Analysis(
      whyItMatters: "Exploit tools (Metasploit, Cobalt Strike) indicate pentesting or compromise.",
      whatsHappening: "\(proc) is a known exploitation framework.",
      severityContext: "Expected for authorized testing. Critical if unexpected.",
      recommendedAction: "If not your pentest, treat as active compromise.")
    }
    exact["Exploit Tool Installed"] = { proc, _, _ in Analysis(
      whyItMatters: "Installed exploit tools could be used for later attacks.",
      whatsHappening: "\(proc) (a known exploit tool) is installed on disk.",
      severityContext: "Expected for security researchers. Remove if unused.",
      recommendedAction: "Verify you installed this. Remove to reduce attack surface.")
    }
    exact["Gatekeeper Bypass"] = { proc, _, _ in Analysis(
      whyItMatters: "Gatekeeper prevents execution of unverified software.",
      whatsHappening: "\(proc) appears to have bypassed Gatekeeper.",
      severityContext: "Some dev workflows bypass Gatekeeper. Malware also does this.",
      recommendedAction: "Verify the binary's origin and code signature.")
    }
  }

  // MARK: - TCC & Misc

  private static func addMiscTechniques(_ exact: inout [String: F]) {
    exact["Suspicious TCC Grant"] = { proc, _, _ in Analysis(
      whyItMatters: "TCC grants control access to camera, mic, screen, disk.",
      whatsHappening: "\(proc) has a TCC permission that may be excessive.",
      severityContext: "Review if app needs this. Some grants persist after uninstall.",
      recommendedAction: "Check System Settings > Privacy. Revoke if unnecessary.")
    }
    exact["Surveillance TCC Grant"] = { proc, _, _ in Analysis(
      whyItMatters: "Screen recording and accessibility allow monitoring all user activity.",
      whatsHappening: "\(proc) has surveillance-capable permissions.",
      severityContext: "Expected for screen sharing, IDEs, accessibility apps.",
      recommendedAction: "Verify \(proc) needs these. Revoke if not.")
    }
    exact["Ransomware Behavior"] = { proc, _, _ in Analysis(
      whyItMatters: "Ransomware encrypts files and demands payment. Early detection is critical.",
      whatsHappening: "\(proc) shows ransomware behavior: rapid file modification + high entropy.",
      severityContext: "Critical if unexpected. Could be FileVault or disk image creation.",
      recommendedAction: "STOP the process immediately. Disconnect from network. Check backups.")
    }
  }

  // MARK: - Prefix Matchers (dynamic technique names)

  private static func addPrefixMatchers(_ prefix: inout [(String, F)]) {
    prefix.append(("Kext Hooks", { proc, _, _ in Analysis(
      whyItMatters: "Kext hooks can intercept or modify any OS operation.",
      whatsHappening: "\(proc.isEmpty ? "A kext" : proc) is hooking kernel functions.",
      severityContext: "Security tools and virtualization use kext hooks. Rootkits also.",
      recommendedAction: "Verify the kext's publisher.") }))
    prefix.append(("Credential Access:", { proc, _, _ in Analysis(
      whyItMatters: "Credential access may indicate password theft or dumping.",
      whatsHappening: "\(proc) is accessing credential-related resources.",
      severityContext: "Browsers and password managers do this legitimately.",
      recommendedAction: "Verify \(proc) has a legitimate reason.") }))
    prefix.append(("DYLD_INSERT_LIBRARIES", { proc, _, _ in Analysis(
      whyItMatters: "DYLD_INSERT_LIBRARIES forces dylib injection into processes.",
      whatsHappening: "\(proc) has DYLD_INSERT_LIBRARIES set.",
      severityContext: "Used by debugging tools. Malware uses it for persistence.",
      recommendedAction: "Check what dylib is injected. Remove if unexpected.") }))
    prefix.append(("Shell Profile", { proc, _, _ in Analysis(
      whyItMatters: "Shell profile mods execute code every terminal open — reliable persistence.",
      whatsHappening: "\(proc.isEmpty ? "A shell profile" : proc) contains suspicious injection.",
      severityContext: "Devs customize profiles. Check for DYLD_ variables.",
      recommendedAction: "Review ~/.zshrc, ~/.bash_profile. Remove unfamiliar entries.") }))
    prefix.append(("Plist", { proc, _, _ in Analysis(
      whyItMatters: "Plist env injection persists across reboots via launchd.",
      whatsHappening: "\(proc.isEmpty ? "A plist" : proc) sets DYLD_ environment variables.",
      severityContext: "Rarely legitimate.",
      recommendedAction: "Remove DYLD entries. Investigate who created it.") }))
    prefix.append(("Suspicious", { proc, _, _ in Analysis(
      whyItMatters: "Flagged as unusual compared to expected configuration.",
      whatsHappening: "\(proc.isEmpty ? "An item" : proc) deviates from normal patterns.",
      severityContext: "May be legitimate or an indicator of compromise.",
      recommendedAction: "Review details and verify origin.") }))
  }
}
