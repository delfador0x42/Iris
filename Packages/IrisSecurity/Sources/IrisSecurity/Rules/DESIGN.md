# Rules — Detection Rule Definitions

## What This Does
Declarative detection rules matched against real-time ES events by
DetectionEngine. Rules define what pattern to match (event type, process,
path) and what to emit (alert with severity and MITRE ID).

## Why This Design
Rules are data, not code. Each rule file covers one MITRE tactic. New rules
can be added without modifying the engine. CorrelationRules define multi-event
patterns (e.g., credential access followed by network exfiltration).

## Data Flow
```
ES Event → DetectionEngine → iterate Rules → match() → Alert
Multiple Alerts → CorrelationRules → multi-event pattern → Correlation
```

## Decisions Made
- Swift structs over YAML/JSON — compile-time validation, no parsing overhead
- One file per tactic — APT, C2, credential theft, persistence, evasion,
  injection, exfiltration, correlation
- RuleLoader exists for future external rule loading but currently unused

## Key Files
- APTRules.swift — targeted attack patterns (Lazarus, APT28, etc.)
- C2Rules.swift — command & control communication patterns
- CredentialTheftRules.swift — keychain, browser, TCC database access
- PersistenceRules.swift — launchd, login items, cron, shell profiles
- CorrelationRules.swift — multi-event attack chain patterns
