import Foundation

// MARK: - Known macOS process database

extension ProcessKnowledgeBase {

    // swiftlint:disable:next function_body_length
    static let knownProcesses: [String: Info] = {
        typealias I = Info; typealias C = Category
        return [
            // Kernel & core
            "kernel_task":          I(description: "Kernel — manages memory, I/O, scheduling", category: .kernel, subsystem: "xnu", isSystemCritical: true),
            "launchd":              I(description: "PID 1 — system/user service manager (init)", category: .kernel, subsystem: "launchd", isSystemCritical: true),
            "kextd":                I(description: "Kernel extension daemon — loads/unloads kexts", category: .kernel, subsystem: "kext", isSystemCritical: true),
            "kernelmanagerd":       I(description: "Manages kernel extension approval and loading", category: .kernel, subsystem: "kext"),
            "sysmond":              I(description: "System resource monitor — CPU/mem/disk stats", category: .kernel, subsystem: "diagnostics"),
            "watchdogd":            I(description: "Hardware watchdog timer daemon", category: .kernel, subsystem: "diagnostics"),

            // Network daemons
            "configd":              I(description: "System configuration — network settings, DNS", category: .network, subsystem: "SystemConfiguration", isSystemCritical: true),
            "mDNSResponder":        I(description: "Bonjour/mDNS — ALL system DNS resolution", category: .network, subsystem: "mDNSResponder", expectedConnections: ["*"], isSystemCritical: true),
            "discoveryd":           I(description: "DNS resolution and network service discovery", category: .network, subsystem: "dns"),
            "netbiosd":             I(description: "NetBIOS name resolution for SMB/Windows networks", category: .network, subsystem: "smb"),
            "symptomsd":            I(description: "Network diagnostics and symptom reporting", category: .network, subsystem: "diagnostics", expectedConnections: ["*.apple.com"]),
            "WiFiAgent":            I(description: "Wi-Fi connection management agent", category: .network, subsystem: "wifi"),
            "airportd":             I(description: "Wi-Fi subsystem daemon", category: .network, subsystem: "wifi", isSystemCritical: true),
            "apsd":                 I(description: "Apple Push Notification daemon", category: .network, subsystem: "apns", expectedConnections: ["*.push.apple.com", "*.apple.com"]),
            "identityservicesd":    I(description: "iMessage/FaceTime identity and key management", category: .network, subsystem: "ids", expectedConnections: ["*.apple.com", "*.icloud.com"]),
            "nsurlsessiond":        I(description: "Background URL session downloads/uploads", category: .network, subsystem: "Foundation", expectedConnections: ["*"]),
            "networkserviceproxy":  I(description: "Relay network traffic for iCloud Private Relay", category: .network, subsystem: "relay", expectedConnections: ["*.apple.com"]),
            "networkd":             I(description: "Low-level network daemon — NWConnection, QUIC, TCP/IP", category: .network, subsystem: "Network", isSystemCritical: true),

            // Storage & filesystem
            "fseventsd":            I(description: "File system event broker — notifies watchers of changes", category: .storage, subsystem: "fsevents", isSystemCritical: true),
            "diskarbitrationd":     I(description: "Disk mount/unmount arbitration", category: .storage, subsystem: "DiskArbitration", isSystemCritical: true),
            "distnoted":            I(description: "Distributed notification daemon", category: .systemDaemon, subsystem: "Foundation"),
            "notifyd":              I(description: "System notification center daemon (notify(3))", category: .systemDaemon, subsystem: "libnotify"),
            "mds":                  I(description: "Metadata server — Spotlight indexing coordinator", category: .storage, subsystem: "Spotlight", isSystemCritical: true),
            "mds_stores":           I(description: "Spotlight index storage and query engine", category: .storage, subsystem: "Spotlight"),
            "mdworker":             I(description: "Spotlight importer worker process", category: .storage, subsystem: "Spotlight"),
            "mdworker_shared":      I(description: "Shared Spotlight importer for multiple file types", category: .storage, subsystem: "Spotlight"),
            "revisiond":            I(description: "File versioning daemon (Time Machine local snapshots)", category: .storage, subsystem: "DocumentVersions", expectedConnections: ["*.icloud.com", "*.apple.com"]),
            "backupd":              I(description: "Time Machine backup daemon", category: .storage, subsystem: "TimeMachine"),
            "mobiletimerd":         I(description: "Timer-based scheduling daemon", category: .systemDaemon, subsystem: "scheduler"),

            // Security
            "securityd":            I(description: "Security framework daemon — keychain, certs, trust", category: .security, subsystem: "Security", isSystemCritical: true),
            "trustd":               I(description: "Certificate trust evaluation daemon", category: .security, subsystem: "Security", expectedConnections: ["*.apple.com", "ocsp.digicert.com", "ocsp.sectigo.com", "crl.apple.com"], isSystemCritical: true),
            "coreauthd":            I(description: "LocalAuthentication — Touch ID / password prompts", category: .security, subsystem: "LocalAuthentication", isSystemCritical: true),
            "opendirectoryd":       I(description: "Directory services — user/group authentication", category: .security, subsystem: "OpenDirectory", expectedConnections: ["*.apple.com"], isSystemCritical: true),
            "SecurityAgent":        I(description: "GUI authorization prompts (admin password dialogs)", category: .security, subsystem: "Security"),
            "authd":                I(description: "Authorization services daemon", category: .security, subsystem: "Security", isSystemCritical: true),
            "endpointsecurityd":    I(description: "Endpoint Security framework event broker", category: .security, subsystem: "EndpointSecurity", isSystemCritical: true),
            "syspolicyd":           I(description: "System policy — Gatekeeper enforcement", category: .security, subsystem: "SystemPolicy", expectedConnections: ["*.apple.com", "api.apple-cloudkit.com"], isSystemCritical: true),
            "XProtectService":      I(description: "XProtect malware signature scanning", category: .security, subsystem: "XProtect", expectedConnections: ["*.apple.com"]),
            "amfid":                I(description: "Apple Mobile File Integrity — code signature validation", category: .security, subsystem: "AMFI", isSystemCritical: true),
            "tccd":                 I(description: "Transparency Consent Control — privacy permission enforcement", category: .security, subsystem: "TCC", isSystemCritical: true),
            "taskgated":            I(description: "Task port access gating (task_for_pid authorization)", category: .security, subsystem: "taskgated", isSystemCritical: true),
            "sandboxd":             I(description: "App Sandbox enforcement daemon", category: .security, subsystem: "Sandbox", isSystemCritical: true),
            "secinitd":             I(description: "Security initialization for sandboxed processes", category: .security, subsystem: "Sandbox"),
            "containermanagerd":    I(description: "App container (sandbox) directory management", category: .security, subsystem: "Container"),
            "biomed":               I(description: "Biometric (Touch ID / Face ID) data management", category: .security, subsystem: "Biometric"),

            // Graphics & UI
            "WindowServer":         I(description: "Core graphics compositor — all screen rendering", category: .graphics, subsystem: "CoreGraphics", isSystemCritical: true),
            "Dock":                 I(description: "Dock, Launchpad, Mission Control, spaces", category: .graphics, subsystem: "Dock", isSystemCritical: true),
            "Finder":               I(description: "File manager and desktop", category: .graphics, subsystem: "Finder", expectedConnections: ["*.apple.com", "*.icloud.com"], isSystemCritical: true),
            "SystemUIServer":       I(description: "Menu bar extras (clock, battery, volume, etc.)", category: .graphics, subsystem: "SystemUI", isSystemCritical: true),
            "loginwindow":          I(description: "Login window and user session management", category: .graphics, subsystem: "loginwindow", isSystemCritical: true),
            "ControlCenter":        I(description: "Control Center panel (Wi-Fi, BT, Sound toggles)", category: .graphics, subsystem: "ControlCenter"),
            "NotificationCenter":   I(description: "Notification Center and widgets", category: .graphics, subsystem: "UserNotifications"),
            "UserNotificationCenter": I(description: "Notification delivery and display service", category: .graphics, subsystem: "UserNotifications"),
            "ViewBridgeAuxiliary":  I(description: "Cross-process view hosting for system UI elements", category: .graphics, subsystem: "ViewBridge"),
            "ControlCenterHelper":  I(description: "Helper for Control Center module rendering", category: .graphics, subsystem: "ControlCenter"),

            // Intelligence & ML
            "proactivated":         I(description: "Proactive suggestions engine (Siri, Spotlight suggestions)", category: .systemAgent, subsystem: "Proactive"),
            "intelligenceplatformd": I(description: "Apple Intelligence / on-device ML coordination", category: .systemAgent, subsystem: "Intelligence"),
            "geoanalyticsd":        I(description: "Location analytics and significant location tracking", category: .systemAgent, subsystem: "CoreLocation"),
            "proactiveeventrackerd": I(description: "Tracks user events for proactive suggestion learning", category: .systemAgent, subsystem: "Proactive"),
            "siriknowledged":       I(description: "Siri knowledge graph and entity resolution", category: .systemAgent, subsystem: "Siri"),
            "siriactionsd":         I(description: "Siri Shortcuts actions execution", category: .systemAgent, subsystem: "Siri"),
            "suggestd":             I(description: "Content suggestion engine for Siri/Spotlight", category: .systemAgent, subsystem: "Suggestions"),
            "coreduetd":            I(description: "Usage pattern learning for predictive features", category: .systemAgent, subsystem: "CoreDuet"),
            "knowledgeconstructiond": I(description: "Builds knowledge graph from on-device data", category: .systemAgent, subsystem: "Knowledge"),
            "mediaanalysisd":       I(description: "Photo/video ML analysis (faces, scenes, objects)", category: .media, subsystem: "MediaAnalysis"),
            "photoanalysisd":       I(description: "Photos library ML classification and search", category: .media, subsystem: "Photos"),
            "triald":               I(description: "A/B testing framework for system feature rollouts", category: .systemDaemon, subsystem: "Trial"),

            // Media
            "coreaudiod":           I(description: "Core Audio daemon — audio routing and mixing", category: .media, subsystem: "CoreAudio", isSystemCritical: true),
            "audioclocksyncd":      I(description: "Audio clock synchronization for AirPlay", category: .media, subsystem: "CoreAudio"),
            "mediaremoted":         I(description: "Media playback remote control (Now Playing)", category: .media, subsystem: "MediaRemote"),
            "avconferenced":        I(description: "Audio/video conferencing (FaceTime)", category: .media, subsystem: "AVConference", expectedConnections: ["*.apple.com"]),
            "VDCAssistant":         I(description: "Video digitizer (camera) framework daemon", category: .media, subsystem: "CoreMediaIO", isSystemCritical: true),
            "cameracaptured":       I(description: "Camera capture session management", category: .media, subsystem: "Camera"),

            // Cloud & sync
            "cloudd":               I(description: "CloudKit sync daemon", category: .systemDaemon, subsystem: "CloudKit", expectedConnections: ["*.apple.com", "*.icloud.com"]),
            "bird":                 I(description: "iCloud Drive file coordination daemon", category: .systemDaemon, subsystem: "iCloudDrive", expectedConnections: ["*.icloud.com", "*.apple.com"]),
            "sharingd":             I(description: "AirDrop, Handoff, shared clipboard", category: .systemDaemon, subsystem: "Sharing"),
            "remindd":              I(description: "Reminders sync and notification daemon", category: .systemAgent, subsystem: "Reminders", expectedConnections: ["*.apple.com", "*.icloud.com"]),
            "CalendarAgent":        I(description: "Calendar sync and notification agent", category: .systemAgent, subsystem: "Calendar", expectedConnections: ["*.apple.com", "*.icloud.com"]),
            "contactsd":            I(description: "Contacts database sync daemon", category: .systemAgent, subsystem: "Contacts", expectedConnections: ["*.apple.com", "*.icloud.com"]),

            // System agents
            "UserEventAgent":       I(description: "Loads system event plugins (USB, disk, display)", category: .systemAgent, subsystem: "UserEventAgent"),
            "cfprefsd":             I(description: "Preferences (UserDefaults/CFPreferences) daemon", category: .systemDaemon, subsystem: "CoreFoundation", isSystemCritical: true),
            "lsd":                  I(description: "Launch Services daemon — app registration, file types", category: .systemDaemon, subsystem: "LaunchServices", isSystemCritical: true),
            "runningboardd":        I(description: "Process lifecycle management (jetsam, assertions)", category: .systemDaemon, subsystem: "RunningBoard"),
            "dasd":                 I(description: "Duet Activity Scheduler — background task scheduling", category: .systemDaemon, subsystem: "DAS", isSystemCritical: true),
            "logd":                 I(description: "Unified logging daemon (os_log)", category: .systemDaemon, subsystem: "Logging", isSystemCritical: true),
            "diagnosticd":          I(description: "System diagnostics and crash report collection", category: .systemDaemon, subsystem: "Diagnostics", expectedConnections: ["*.apple.com"]),
            "ReportCrash":          I(description: "Crash report generator for crashed processes", category: .systemDaemon, subsystem: "CrashReporter", expectedConnections: ["*.apple.com"]),
            "syslogd":              I(description: "Legacy syslog daemon", category: .systemDaemon, subsystem: "syslog"),
            "coreservicesd":        I(description: "Core Services coordination — app launch, file types", category: .systemDaemon, subsystem: "CoreServices"),
            "iconservicesagent":    I(description: "App icon caching and rendering", category: .systemAgent, subsystem: "IconServices"),
            "locationd":            I(description: "Location services daemon — GPS, Wi-Fi positioning", category: .systemDaemon, subsystem: "CoreLocation", expectedConnections: ["gs-loc.apple.com", "*.apple.com"], isSystemCritical: true),
            "bluetoothd":           I(description: "Bluetooth stack daemon", category: .systemDaemon, subsystem: "Bluetooth", isSystemCritical: true),
            "usbd":                 I(description: "USB device management daemon", category: .systemDaemon, subsystem: "USB"),
            "thermald":             I(description: "Thermal management — CPU throttling under heat", category: .systemDaemon, subsystem: "Thermal", isSystemCritical: true),
            "powerd":               I(description: "Power management — sleep, wake, battery", category: .systemDaemon, subsystem: "Power", isSystemCritical: true),
            "ioupsd":               I(description: "UPS/battery monitoring daemon", category: .systemDaemon, subsystem: "Power"),
            "displaypolicyd":       I(description: "Display brightness and True Tone policy", category: .systemDaemon, subsystem: "Display"),

            // Dev tools
            "Xcode":                I(description: "Apple IDE for macOS/iOS development", category: .devTool, subsystem: "Xcode", expectedConnections: ["developer.apple.com", "*.apple.com"]),
            "swift-frontend":       I(description: "Swift compiler frontend", category: .devTool, subsystem: "Swift"),
            "clang":                I(description: "C/C++/ObjC compiler (LLVM)", category: .devTool, subsystem: "LLVM"),
            "ld":                   I(description: "Apple linker", category: .devTool, subsystem: "LLVM"),
            "lldb-rpc-server":      I(description: "LLDB debugger RPC server", category: .devTool, subsystem: "LLDB"),
            "IBDesignablesAgent":   I(description: "Interface Builder live rendering agent", category: .devTool, subsystem: "Xcode"),
            "sourcekit-lsp":        I(description: "Swift/ObjC language server protocol daemon", category: .devTool, subsystem: "SourceKit"),
            "ibtool":               I(description: "Interface Builder compilation tool", category: .devTool, subsystem: "Xcode"),
            "xcodebuild":           I(description: "Xcode command-line build tool", category: .devTool, subsystem: "Xcode"),
            "xcrun":                I(description: "Xcode tool path resolver", category: .devTool, subsystem: "Xcode"),

            // Common user apps
            "Safari":               I(description: "Apple web browser", category: .userApp, subsystem: "Safari", expectedConnections: ["*"]),
            "com.apple.WebKit.Networking": I(description: "WebKit network process — handles HTTP for Safari/WKWebView", category: .network, subsystem: "WebKit", expectedConnections: ["*"]),
            "com.apple.WebKit.WebContent": I(description: "WebKit render process — one per tab", category: .userApp, subsystem: "WebKit"),
            "Terminal":             I(description: "Terminal emulator", category: .userApp, subsystem: "Terminal"),
            "Activity Monitor":     I(description: "System resource monitor GUI", category: .userApp, subsystem: "ActivityMonitor"),
            "Mail":                 I(description: "Apple Mail client", category: .userApp, subsystem: "Mail", expectedConnections: ["*"]),
            "Messages":             I(description: "iMessage and SMS client", category: .userApp, subsystem: "Messages", expectedConnections: ["*.apple.com", "*.icloud.com"]),
            "TextEdit":             I(description: "Basic text editor", category: .userApp, subsystem: "TextEdit"),

            // Misc services
            "AMPLibraryAgent":      I(description: "Apple Music/iTunes library management", category: .media, subsystem: "Music"),
            "storedownloadd":       I(description: "App Store / software update downloads", category: .systemDaemon, subsystem: "AppStore", expectedConnections: ["*.apple.com", "*.mzstatic.com"]),
            "softwareupdated":      I(description: "macOS software update daemon", category: .systemDaemon, subsystem: "SoftwareUpdate", expectedConnections: ["*.apple.com", "mesu.apple.com", "swscan.apple.com"]),
            "rapportd":             I(description: "Device proximity and Handoff communication", category: .network, subsystem: "Rapport"),
            "timed":                I(description: "NTP time synchronization daemon", category: .systemDaemon, subsystem: "Time", expectedConnections: ["time.apple.com"]),
            "cron":                 I(description: "Classic Unix task scheduler", category: .systemDaemon, subsystem: "cron"),
            "cupsd":                I(description: "CUPS printing system daemon", category: .systemDaemon, subsystem: "CUPS"),
            "sshd":                 I(description: "OpenSSH server daemon", category: .network, subsystem: "SSH"),
            "pboard":               I(description: "Pasteboard (clipboard) server", category: .systemDaemon, subsystem: "AppKit"),
            "universalaccessd":     I(description: "Accessibility features daemon", category: .systemAgent, subsystem: "Accessibility"),
            "TextInputMenuAgent":   I(description: "Input method switching (keyboard layouts)", category: .systemAgent, subsystem: "TextInput"),
            "fontd":                I(description: "Font management and validation daemon", category: .systemDaemon, subsystem: "CoreText"),
            "corebrightnessd":      I(description: "Display brightness auto-adjustment", category: .systemDaemon, subsystem: "Display"),
            "mediaremoteagent":     I(description: "Media remote control agent (AirPlay targets)", category: .media, subsystem: "MediaRemote"),
            "peopled":              I(description: "Contacts/people suggestion engine", category: .systemAgent, subsystem: "Contacts"),
            "corespeechd":          I(description: "Speech recognition daemon (Dictation, Siri)", category: .systemDaemon, subsystem: "CoreSpeech"),
            "media-indexer":        I(description: "Media library indexing for Spotlight", category: .media, subsystem: "Spotlight"),
            "corespotlightd":       I(description: "Core Spotlight index management", category: .storage, subsystem: "Spotlight"),
            "extensionkitservice":  I(description: "App extension hosting and lifecycle", category: .systemDaemon, subsystem: "ExtensionKit"),
            "nesessionmanager":     I(description: "Network Extension session management (VPN, content filter)", category: .network, subsystem: "NetworkExtension"),
            "nehelper":             I(description: "Network Extension helper (VPN, DNS proxy)", category: .network, subsystem: "NetworkExtension"),
            "wirelessproxd":        I(description: "Wireless proximity daemon (AirDrop, Handoff BLE)", category: .network, subsystem: "WirelessProximity"),
            "analyticsd":           I(description: "Analytics daemon — usage analytics for Apple", category: .systemDaemon, subsystem: "Analytics", expectedConnections: ["*.apple.com"]),
            "Iris":                 I(description: "Iris EDR — this application", category: .security, subsystem: "Iris"),
        ]
    }()
}
