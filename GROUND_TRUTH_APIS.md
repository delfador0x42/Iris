# Ground Truth APIs — Undocumented & Low-Level macOS Probing

## Philosophy

Never ask the OS "is this normal?" — the OS is the enemy.
Instead: **force the system to reveal its true state through action, not reporting.**

Every probe must answer 5 questions:
1. **What lie does this detect?**
2. **What ground truth source makes the lie detectable?**
3. **Can the adversary defeat this, and at what cost?**
4. **What does a positive detection look like?**
5. **What is the false positive rate?**

Build **contradiction engines**: gather the same fact from 3+ independent sources.
If sources disagree, someone is lying.

---

## Verified Working APIs (macOS 26, Apple Silicon, SIP partially disabled)

### 1. `kas_info` — Kernel Address Space Layout

```swift
@_silgen_name("kas_info")
func kas_info(_ selector: Int32, _ value: UnsafeMutableRawPointer, _ size: UnsafeMutablePointer<Int>) -> Int32

// Selector 0 = KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR
var slide: UInt64 = 0
var size = MemoryLayout<UInt64>.size
kas_info(0, &slide, &size)  // Returns kernel ASLR slide: 0x31514000
```

- **What it gives you**: Kernel ASLR slide. Changes every boot. Ground truth for boot identity.
- **Lie it detects**: "This system hasn't been rebooted" when it has (slide changed). Or kernel memory tampering (slide inconsistent with mapped addresses).
- **Adversary cost**: Must hook the kas_info syscall itself, which requires knowing you're checking it. High cost — requires kernel-level interposition.
- **Requires**: Root. CONFIG_KAS_INFO must be enabled (it is on macOS).

### 2. `csr_get_active_config` + `csr_check` + Behavioral + NVRAM — 4-Way SIP Verification

```swift
@_silgen_name("csr_get_active_config")
func csr_get_active_config(_ config: UnsafeMutablePointer<UInt32>) -> Int32

@_silgen_name("csr_check")
func csr_check(_ mask: UInt32) -> Int32

// Source 1: What does the config register say?
var config: UInt32 = 0
csr_get_active_config(&config)  // 0x86f on this machine

// Source 2: Per-flag behavioral check via kernel
let flags: [(String, UInt32)] = [
    ("CSR_ALLOW_UNTRUSTED_KEXTS",       0x1),
    ("CSR_ALLOW_UNRESTRICTED_FS",        0x2),
    ("CSR_ALLOW_TASK_FOR_PID",           0x4),
    ("CSR_ALLOW_KERNEL_DEBUGGER",        0x8),
    ("CSR_ALLOW_APPLE_INTERNAL",         0x10),
    ("CSR_ALLOW_UNRESTRICTED_DTRACE",    0x20),
    ("CSR_ALLOW_UNRESTRICTED_NVRAM",     0x40),
    ("CSR_ALLOW_DEVICE_CONFIGURATION",   0x80),
    ("CSR_ALLOW_ANY_RECOVERY_OS",        0x100),
    ("CSR_ALLOW_UNAPPROVED_KEXTS",       0x200),
]
for (name, flag) in flags {
    let allowed = csr_check(flag) == 0
    let reported = (config & flag) != 0
    // If allowed != reported → CONTRADICTION
}

// Source 3: Behavioral — actually try a SIP-protected operation
try Data([0x42]).write(to: URL(fileURLWithPath: "/System/Library/.probe"))
// Success = SIP filesystem protection OFF. Failure = ON.
// CRITICAL: On Apple Silicon, CSR_ALLOW_UNRESTRICTED_FS can be set
// but /System writes STILL FAIL due to Authenticated Root Volume (sealed snapshot).
// This is a REAL contradiction this probe catches.

// Source 4: NVRAM direct read via IOKit (bypasses nvram command)
let nvram = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IODTNVRAM"))
IORegistryEntryCreateCFProperty(nvram, "csr-active-config" as CFString, kCFAllocatorDefault, 0)
```

- **VERIFIED FINDING**: On this machine, csr_get_active_config=0x86f (SIP OFF) and csr_check agrees, but /System write FAILS. This is because Apple Silicon's Authenticated Root Volume is a *separate* protection from CSR. A nation-state could set CSR flags to make SIP *look* disabled while ARV still protects the system volume — or vice versa.

### 3. `__mac_syscall` — MAC Policy Framework Probing

```c
extern int __mac_syscall(const char *policy, int call, void *arg);

// Probe which MAC policies are loaded in the kernel
__mac_syscall("Sandbox", 0, NULL);   // errno=EFAULT  → LOADED (tried to read arg)
__mac_syscall("AMFI", 0, NULL);      // errno=ENOSYS  → LOADED (call not implemented)
__mac_syscall("Quarantine", 0, NULL); // errno=ENOSYS  → LOADED
__mac_syscall("TMSafetyNet", 0, NULL); // errno=ENOENT(103) → NOT LOADED
__mac_syscall("endpointsecurity", 0, NULL); // errno=103 → NOT LOADED (it's not a MAC policy)
```

- **What it gives you**: Ground truth about which Mandatory Access Control policies the kernel has loaded.
- **Lie it detects**: A rootkit that injects a custom MAC policy to intercept security checks. If a policy appears that shouldn't exist, or a standard policy is missing, the kernel has been tampered with.
- **Error code semantics**: EFAULT/EINVAL/ENOSYS = policy EXISTS. ENOENT(103) = policy NOT registered.
- **Known policies on clean macOS**: Sandbox, AMFI, Quarantine (3 policies). Anything else is suspicious.

### 4. `necp_open` / `necp_session_open` — Kernel Network Policy Engine

```c
extern int necp_open(int flags);           // Returns fd to kernel NECP
extern int necp_session_open(int flags);   // Returns policy session fd
extern int necp_client_action(int necp_fd, uint32_t action, ...);
extern int necp_match_policy(uint8_t *parameters, size_t parameters_size, void *returned_result);
```

- **What it gives you**: Direct access to the kernel's Network Extension Control Protocol. This is the policy engine that decides which network extension handles which traffic.
- **Lie it detects**: Hidden network filters. If a network extension is intercepting traffic but not visible via NEConfigurationManager, NECP knows about it.
- **Tested**: `necp_open(0)` returns fd=3 (success). `necp_session_open(0)` returns -1 (needs entitlement for policy sessions).

### 5. `proc_listallpids` + `proc_pidinfo` + `proc_pidpath` — Process Ground Truth

```swift
@_silgen_name("proc_listallpids")
func proc_listallpids(_ buffer: UnsafeMutableRawPointer?, _ buffersize: Int32) -> Int32

@_silgen_name("proc_pidinfo")
func proc_pidinfo(_ pid: Int32, _ flavor: Int32, _ arg: UInt64,
                  _ buffer: UnsafeMutableRawPointer?, _ buffersize: Int32) -> Int32

@_silgen_name("proc_pidpath")
func proc_pidpath(_ pid: Int32, _ buffer: UnsafeMutableRawPointer, _ buffersize: UInt32) -> Int32

// PROC_PIDARCHINFO (flavor 19) — CPU architecture per process
struct proc_archinfo { var p_cputype: Int32; var p_cpusubtype: Int32 }
// ARM64 = 0x100000C (native), x86_64 = 0x1000007 (Rosetta)
// Rosetta processes on an ARM64-only system = suspicious

// PROC_PIDREGIONPATHINFO (flavor 8) — full memory map with file paths
// PROC_PIDTASKINFO (flavor 4) — task-level info (threads, memory)
// PROC_PIDFDVNODEPATHINFO (flavor 2 on FD) — open file descriptors with paths
```

- **What it gives you**: Third enumeration path (separate from sysctl and processor_set_tasks). Architecture per process detects Rosetta translation (x86 malware on ARM system). Memory region paths reveal every loaded binary.
- **Tested**: 163 PIDs, all ARM64 native, zero Rosetta on clean system.

### 6. `proc_listcoalitions` — Kernel Process Grouping

```swift
@_silgen_name("proc_listcoalitions")
func proc_listcoalitions(_ type: UInt32, _ typeorder: UInt32,
                         _ buffer: UnsafeMutableRawPointer?, _ buffersize: Int32) -> Int32

// COALITION_TYPE_RESOURCE = 0, COALITION_TYPE_JETSAM = 1
// JETSAM coalitions returned 18224 bytes on this machine
```

- **What it gives you**: Kernel-level process grouping. Every process belongs to a coalition. This is a FOURTH enumeration path independent of sysctl, proc_listallpids, and processor_set_tasks.
- **Lie it detects**: A process hidden from all three standard enumeration methods but still in a coalition.

### 7. IOKit Direct Registry Reads — Hardware Ground Truth

```swift
import IOKit

// Platform identity (can't be faked without IOKit driver hooks)
let plat = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
IORegistryEntryCreateCFProperty(plat, "IOPlatformUUID" as CFString, ...)     // Hardware UUID
IORegistryEntryCreateCFProperty(plat, "IOPlatformSerialNumber" as CFString, ...) // Serial
IORegistryEntryCreateCFProperty(plat, "model" as CFString, ...)              // Mac15,9
IORegistryEntryCreateCFProperty(plat, "target-type" as CFString, ...)        // J516c

// Kernel version from IOKit (separate from uname/sysctl)
let root = IORegistryGetRootEntry(kIOMainPortDefault)
IORegistryEntryCreateCFProperty(root, "IOKitBuildVersion" as CFString, ...)
IORegistryEntryCreateCFProperty(root, "OS Build Version" as CFString, ...)

// NVRAM direct (bypasses nvram command-line tool)
let nvram = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IODTNVRAM"))
// Read: csr-active-config, boot-args, auto-boot

// USB device enumeration (detect rogue devices, rubber duckies)
IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOUSBHostDevice"), &iter)
// Read: idVendor, idProduct, device name

// Secure Enclave presence
IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleSEPManager"))
// HasXART=1 confirms SEP is active

// SMC presence (hardware sensors)
IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleSMC"))
```

- **What it gives you**: Hardware identity from the IOKit device tree, which is populated by the kernel at boot from firmware. Separate trust chain from sysctl.
- **Adversary cost**: Must hook IOKit registry calls or modify the device tree in kernel memory. Extremely expensive — requires persistent kernel-level access AND knowledge of exactly which IOKit paths you're reading.

### 8. `processor_set_tasks` — Kernel Task Walk (Already Implemented)

```swift
// host_processor_set_priv → processor_set_tasks → pid_for_task
// Walks ALL Mach tasks in kernel. Fourth process enumeration layer.
// See HiddenProcessDetector.swift for full implementation.
```

### 9. `csops` — Kernel Code Signing Flags

```swift
@_silgen_name("csops")
func csops(_ pid: Int32, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

// CS_OPS_STATUS = 0 → returns cs_flags
// Key flags: CS_VALID, CS_DEBUGGED (task_for_pid was used!), CS_HARD, CS_KILL,
//            CS_PLATFORM_BINARY, CS_RUNTIME, CS_RESTRICT
```

- **Lie it detects**: CS_DEBUGGED means someone called task_for_pid on this process — canonical injection indicator.

### 10. Sysctl Hardware Ground Truth

```swift
// These are kernel-populated, separate from IOKit
// kern.bootsessionuuid — changes every boot (cross-check with kas_info slide)
// kern.boottime — exact boot timestamp
// kern.osversion — build number (25D125)
// hw.target — hardware target (J516cAP)
// hw.model — model identifier (Mac15,9)
// machdep.cpu.brand_string — CPU identity (Apple M3 Max)
```

---

## Cross-Reference Matrix

For maximum detection, gather the same fact from multiple independent sources:

| Fact | Source 1 | Source 2 | Source 3 | Source 4 |
|------|----------|----------|----------|----------|
| **SIP state** | csr_get_active_config | csr_check per-flag | Behavioral /System write | NVRAM IOKit csr-active-config |
| **Process list** | sysctl KERN_PROC_ALL | proc_listallpids | processor_set_tasks | proc_listcoalitions |
| **Boot identity** | kern.bootsessionuuid | kas_info KASLR slide | kern.boottime | IOKit IOKitBuildVersion |
| **Hardware identity** | sysctl hw.model | IOKit IOPlatformExpertDevice | IOKit target-type | IOKit serial |
| **Code signing** | SecStaticCode API | csops() kernel flags | LC_CODE_SIGNATURE parse | dyld shared cache UUID |
| **Loaded code** | TASK_DYLD_INFO images | mach_vm_region walk | PROC_PIDREGIONPATHINFO | on-disk Mach-O deps |
| **MAC policies** | __mac_syscall probe | Expected: Sandbox+AMFI+Quarantine | — | — |
| **CPU architecture** | proc_pidinfo ARCHINFO | Mach-O header cputype | sysctl hw.cputype | — |
| **Network policy** | necp_open fd | NEConfiguration API | proc_pidfdinfo sockets | kernel socket table |

**Rule: If any two sources disagree, flag a contradiction. Three disagreements = high-confidence tampering.**

---

## Discovery Recipe for New APIs

```bash
# 1. Find the framework/library
nm -gU /usr/lib/system/libsystem_kernel.dylib | grep -i keyword
nm -gU /System/Library/PrivateFrameworks/Foo.framework/Foo | grep -i keyword

# 2. Check XNU source for struct definitions
grep -rn 'keyword' /path/to/xnu/bsd/sys/ /path/to/xnu/osfmk/

# 3. Write a test program
cat > /tmp/test.swift << 'EOF'
@_silgen_name("undocumented_func")
func undocumented_func(...) -> Int32
// Test it
EOF
swiftc /tmp/test.swift -o /tmp/test && sudo /tmp/test

# 4. For IOKit: enumerate the registry
ioreg -l -p IOService | grep -i keyword
ioreg -l -p IODeviceTree | grep -i keyword

# 5. Key libraries to mine:
# /usr/lib/system/libsystem_kernel.dylib  — syscalls, Mach traps
# /usr/lib/system/liblaunch.dylib         — launchd communication
# /usr/lib/libnetwork.dylib               — network stack
# /System/Library/Frameworks/IOKit.framework/IOKit — hardware
# /System/Library/PrivateFrameworks/AppleMobileFileIntegrity.framework — AMFI
```

---

## Known Contradictions on This Machine

| Sources | Expected | Actual | Meaning |
|---------|----------|--------|---------|
| csr_get_active_config vs /System write | Both agree | CSR=0x86f (OFF) but write FAILS | Apple Silicon Authenticated Root Volume is separate from CSR. ARV seals /System even when CSR allows unrestricted FS. |
| NVRAM csr-active-config vs csr_get_active_config | Match | NVRAM empty, config=0x86f | CSR was set via recovery mode boot policy, not NVRAM variable. Apple Silicon stores SIP config in LocalPolicy, not NVRAM. |

These are **expected** contradictions on a clean system. Document them so future probes don't false-positive on them. The dangerous contradictions are the ones that AREN'T expected.
