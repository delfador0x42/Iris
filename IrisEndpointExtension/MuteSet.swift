import Foundation
import EndpointSecurity

/// Event-specific muting rules for the ES client.
/// Reduces event volume by muting known-noisy (path, event type) pairs
/// while keeping those same paths visible for other event types.
///
/// Example: Mute OPEN events from /System/Library/Frameworks/* but still
/// see EXEC events from those paths.
struct MuteSet {

    struct EventRule {
        let eventType: es_event_type_t
        let muteType: es_mute_path_type_t
        let paths: [String]
    }

    struct GlobalRule {
        let muteType: es_mute_path_type_t
        let paths: [String]
    }

    let eventRules: [EventRule]
    let globalRules: [GlobalRule]

    /// Apply all muting rules to an ES client.
    func apply(to client: OpaquePointer) -> (eventCount: Int, globalCount: Int) {
        var eventMuted = 0
        var globalMuted = 0

        for rule in eventRules {
            var eventType = rule.eventType
            for path in rule.paths {
                let result = es_mute_path_events(client, path, rule.muteType, &eventType, 1)
                if result == ES_RETURN_SUCCESS { eventMuted += 1 }
            }
        }

        for rule in globalRules {
            for path in rule.paths {
                let result = es_mute_path(client, path, rule.muteType)
                if result == ES_RETURN_SUCCESS { globalMuted += 1 }
            }
        }

        return (eventMuted, globalMuted)
    }

    // MARK: - Default Iris Rules

    static var `default`: MuteSet {
        let home = NSHomeDirectory()
        let cachesDir = "\(home)/Library/Caches"

        let eventRules: [EventRule] = [
            // OPEN: extremely high volume from system frameworks and daemons
            EventRule(eventType: ES_EVENT_TYPE_NOTIFY_OPEN, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/System/Library/Frameworks/",
                "/System/Library/PrivateFrameworks/",
                "/System/Library/CoreServices/",
                "/usr/lib/",
                "/usr/libexec/",
                "/usr/share/",
                "/private/var/db/dyld/",
                "/private/var/db/uuidtext/",
                "/Library/Caches/",
            ]),

            // WRITE: system daemons writing to caches, logs, diagnostics
            EventRule(eventType: ES_EVENT_TYPE_NOTIFY_WRITE, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/private/var/db/uuidtext/",
                "/private/var/folders/",
                "/Library/Caches/",
                cachesDir,
            ]),
            EventRule(eventType: ES_EVENT_TYPE_NOTIFY_WRITE, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/sbin/cfprefsd",
                "/usr/libexec/logd",
            ]),

            // MMAP: system libraries mapped constantly during normal operation
            EventRule(eventType: ES_EVENT_TYPE_NOTIFY_MMAP, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/",
                "/Library/Caches/",
                "/private/var/db/",
            ]),
            EventRule(eventType: ES_EVENT_TYPE_NOTIFY_MMAP, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/libexec/xpcproxy",
                "/usr/libexec/spindump",
                "/usr/bin/tailspin",
                "/usr/libexec/opendirectoryd",
            ]),

            // MPROTECT: system JIT and linker operations
            EventRule(eventType: ES_EVENT_TYPE_NOTIFY_MPROTECT, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/libexec/xpcproxy",
                "/usr/libexec/spindump",
                "/usr/bin/tailspin",
                "/usr/libexec/opendirectoryd",
            ]),

            // XPC_CONNECT: extremely chatty system XPC services
            EventRule(eventType: ES_EVENT_TYPE_NOTIFY_XPC_CONNECT, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/sbin/bluetoothd",
                "/usr/libexec/airportd",
                "/usr/libexec/xpcproxy",
                "/usr/sbin/cfprefsd",
            ]),

            // SETEXTATTR: Spotlight metadata updates
            EventRule(eventType: ES_EVENT_TYPE_NOTIFY_SETEXTATTR, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/System/Library/CoreServices/Spotlight.app",
            ]),
        ]

        // Global: mute ALL events from truly noisy processes
        let globalRules: [GlobalRule] = [
            GlobalRule(muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/libexec/logd",
                "/System/Library/PrivateFrameworks/BiomeStreams.framework/Support/BiomeAgent",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared",
            ]),
        ]

        return MuteSet(eventRules: eventRules, globalRules: globalRules)
    }
}
