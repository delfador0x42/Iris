# Helpers — Cross-Cutting System Utilities

## What This Does
Low-level system interaction wrappers shared across multiple scanners.
Code signing validation, Mach task enumeration, IOKit queries, SQLite reads,
and sysctl calls. These are the syscall-level building blocks.

## Why This Design
Shared because multiple scanners need the same system calls. CodeSignValidator
is used by PersistenceScanner, KextAnomalyDetector, BinaryAnalysisEngine.
Each helper wraps one macOS subsystem — no cross-concern leaking.

## Decisions Made
- CodeSignValidator calls `codesign` CLI — SecStaticCodeRef alternative explored
  but CLI gives richer output (entitlements, team ID, signing authority chain)
- SQLiteReader uses sqlite3 C API directly — no GRDB/SQLite.swift dependency
- SysctlHelper wraps sysctlbyname with type-safe generics
- MachTaskEnumerator uses task_for_pid (requires root or entitlement)

## Key Files
- CodeSignValidator.swift — signing status, entitlements, dangerous entitlements
- MachTaskEnumerator.swift — enumerate Mach tasks for process inspection
- IOKitHelper.swift — IOKit device and driver enumeration
- SQLiteReader.swift — safe SQLite database reading (TCC.db, browser dbs)
- SysctlHelper.swift — typed sysctl queries (kern.bootargs, hw.model, etc.)
